package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"music-backend/internal/models"
	"music-backend/internal/security"
)

// MongoUserStore koristi MongoDB za čuvanje korisnika, a OTP/reset/sesije drži u memoriji.
type MongoUserStore struct {
	client          *mongo.Client
	col             *mongo.Collection
	mu              sync.Mutex
	verificationMap map[string]string
	otpMap          map[string]otpEntry
	resetMap        map[string]resetEntry
	sessions        map[string]string
	magicMap        map[string]resetEntry
}

func NewMongoUserStore(ctx context.Context, uri, dbName, collection string) (*MongoUserStore, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	col := client.Database(dbName).Collection(collection)
	// Unikatni indeksi za username i email.
	_, _ = col.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
	})

	return &MongoUserStore{
		client:          client,
		col:             col,
		verificationMap: make(map[string]string),
		otpMap:          make(map[string]otpEntry),
		resetMap:        make(map[string]resetEntry),
		magicMap:        make(map[string]resetEntry),
		sessions:        make(map[string]string),
	}, nil
}

type mongoUser struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty"`
	Username           string             `bson:"username"`
	FirstName          string             `bson:"firstName"`
	LastName           string             `bson:"lastName"`
	Email              string             `bson:"email"`
	PasswordHash       string             `bson:"passwordHash"`
	Role               string             `bson:"role"`
	Verified           bool               `bson:"verified"`
	PasswordChangedAt  time.Time          `bson:"passwordChangedAt"`
	PasswordExpiresAt  time.Time          `bson:"passwordExpiresAt"`
	RegistrationStatus string             `bson:"registrationStatus"`
	CreatedAt          time.Time          `bson:"createdAt"`
	UpdatedAt          time.Time          `bson:"updatedAt"`
}

func (s *MongoUserStore) Register(u models.User) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Proveri postojanje username/email.
	var tmp mongoUser
	err := s.col.FindOne(ctx, bson.M{"username": u.Username}).Decode(&tmp)
	if err == nil {
		return "", ErrUsernameExists
	}
	err = s.col.FindOne(ctx, bson.M{"email": u.Email}).Decode(&tmp)
	if err == nil {
		return "", ErrEmailExists
	}

	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	tokenHash := security.HashSHA256Hex(token)

	doc := mongoUser{
		Username:           u.Username,
		FirstName:          u.FirstName,
		LastName:           u.LastName,
		Email:              u.Email,
		PasswordHash:       u.PasswordHash,
		Role:               u.Role,
		Verified:           false,
		RegistrationStatus: models.RegistrationPending,
		PasswordChangedAt:  time.Now(),
		PasswordExpiresAt:  time.Now().Add(models.PasswordMaxAge),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if _, err := s.col.InsertOne(ctx, doc); err != nil {
		return "", err
	}
	s.verificationMap[tokenHash] = u.Username
	return token, nil
}

func (s *MongoUserStore) Confirm(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenHash := security.HashSHA256Hex(token)
	username, ok := s.verificationMap[tokenHash]
	if !ok {
		return ErrTokenInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := s.col.UpdateOne(ctx,
		bson.M{"username": username},
		bson.M{"$set": bson.M{"verified": true, "registrationStatus": models.RegistrationActive}},
	)
	if err != nil {
		return err
	}
	if res.ModifiedCount == 0 {
		return ErrUserNotFound
	}
	delete(s.verificationMap, tokenHash)
	return nil
}

func (s *MongoUserStore) Authenticate(username, password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var u mongoUser
	if err := s.col.FindOne(ctx, bson.M{"username": username}).Decode(&u); err != nil {
		return "", ErrUserNotFound
	}
	if time.Now().After(u.PasswordExpiresAt) {
		return "", ErrPasswordExpired
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return "", ErrInvalidCreds
	}
	if !u.Verified {
		return "", ErrTokenInvalid
	}
	code, err := security.GenerateOTPCode()
	if err != nil {
		return "", err
	}
	codeHash := security.HashSHA256Hex(code)
	s.otpMap[codeHash] = otpEntry{Username: username, ExpiresAt: time.Now().Add(10 * time.Minute)}
	return code, nil
}

func (s *MongoUserStore) VerifyOTP(code string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	codeHash := security.HashSHA256Hex(code)
	entry, ok := s.otpMap[codeHash]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return "", ErrOTPInvalid
	}
	delete(s.otpMap, codeHash)
	session, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	s.sessions[session] = entry.Username
	return session, nil
}

func (s *MongoUserStore) Logout(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, session)
}

func (s *MongoUserStore) ChangePassword(username, currentPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var u mongoUser
	if err := s.col.FindOne(ctx, bson.M{"username": username}).Decode(&u); err != nil {
		return ErrUserNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCreds
	}
	if time.Since(u.PasswordChangedAt) < models.PasswordMinAgeForChange {
		return ErrPasswordTooNew
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.col.UpdateOne(ctx,
		bson.M{"username": username},
		bson.M{
			"$set": bson.M{
				"passwordHash":      string(hash),
				"passwordChangedAt": time.Now(),
				"passwordExpiresAt": time.Now().Add(models.PasswordMaxAge),
			},
		},
	)
	return err
}

func (s *MongoUserStore) RequestPasswordReset(email string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var u mongoUser
	if err := s.col.FindOne(ctx, bson.M{"email": email}).Decode(&u); err != nil {
		return "", ErrUserNotFound
	}
	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	tokenHash := security.HashSHA256Hex(token)
	s.resetMap[tokenHash] = resetEntry{
		Username:  u.Username,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	return token, nil
}

func (s *MongoUserStore) ResetPassword(token, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokenHash := security.HashSHA256Hex(token)
	entry, ok := s.resetMap[tokenHash]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return ErrResetInvalid
	}
	delete(s.resetMap, tokenHash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := s.col.UpdateOne(ctx,
		bson.M{"username": entry.Username},
		bson.M{"$set": bson.M{
			"passwordHash":      string(hash),
			"passwordChangedAt": time.Now(),
			"passwordExpiresAt": time.Now().Add(models.PasswordMaxAge),
		}},
	)
	if err != nil {
		return err
	}
	if res.ModifiedCount == 0 {
		return errors.New("nije ažuriran korisnik")
	}
	return nil
}

func (s *MongoUserStore) RequestMagicLink(email string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var u mongoUser
	if err := s.col.FindOne(ctx, bson.M{"email": email}).Decode(&u); err != nil {
		return "", ErrUserNotFound
	}
	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	tokenHash := security.HashSHA256Hex(token)
	s.magicMap[tokenHash] = resetEntry{
		Username:  u.Username,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	return token, nil
}

func (s *MongoUserStore) ConsumeMagicLink(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenHash := security.HashSHA256Hex(token)
	entry, ok := s.magicMap[tokenHash]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return "", ErrMagicInvalid
	}
	delete(s.magicMap, tokenHash)

	session, err := security.GenerateToken()
	if err != nil {
		return "", err
	}
	s.sessions[session] = entry.Username
	return session, nil
}

// VerifyOTPAndGetUser verifikuje OTP i vraća User objekat
func (s *MongoUserStore) VerifyOTPAndGetUser(code string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	codeHash := security.HashSHA256Hex(code)
	entry, ok := s.otpMap[codeHash]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil, ErrOTPInvalid
	}
	delete(s.otpMap, codeHash)

	var mu mongoUser
	if err := s.col.FindOne(ctx, bson.M{"username": entry.Username}).Decode(&mu); err != nil {
		return nil, ErrUserNotFound
	}

	return &models.User{
		ID:                mu.ID.Hex(),
		Username:          mu.Username,
		FirstName:         mu.FirstName,
		LastName:          mu.LastName,
		Email:             mu.Email,
		Role:              mu.Role,
		PasswordHash:      mu.PasswordHash,
		Verified:          mu.Verified,
		PasswordChangedAt: mu.PasswordChangedAt,
		PasswordExpiresAt: mu.PasswordExpiresAt,
	}, nil
}

// ConsumeMagicLinkAndGetUser potvrđuje magic link i vraća User objekat
func (s *MongoUserStore) ConsumeMagicLinkAndGetUser(token string) (*models.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tokenHash := security.HashSHA256Hex(token)
	entry, ok := s.magicMap[tokenHash]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil, ErrMagicInvalid
	}
	delete(s.magicMap, tokenHash)

	var mu mongoUser
	if err := s.col.FindOne(ctx, bson.M{"username": entry.Username}).Decode(&mu); err != nil {
		return nil, ErrUserNotFound
	}

	return &models.User{
		ID:                mu.ID.Hex(),
		Username:          mu.Username,
		FirstName:         mu.FirstName,
		LastName:          mu.LastName,
		Email:             mu.Email,
		Role:              mu.Role,
		PasswordHash:      mu.PasswordHash,
		Verified:          mu.Verified,
		PasswordChangedAt: mu.PasswordChangedAt,
		PasswordExpiresAt: mu.PasswordExpiresAt,
	}, nil
}

// UpdateLastLogin ažurira poslednju prijavu
func (s *MongoUserStore) UpdateLastLogin(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	res, err := s.col.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": bson.M{"updatedAt": time.Now()}})
	if err != nil {
		return err
	}
	if res.ModifiedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpdateUserRole menja ulogu korisnika (2.17)
func (s *MongoUserStore) UpdateUserRole(userID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	res, err := s.col.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": bson.M{"role": role, "updatedAt": time.Now()}})
	if err != nil {
		return err
	}
	if res.ModifiedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}
