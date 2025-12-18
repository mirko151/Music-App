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
	Verified           bool               `bson:"verified"`
	PasswordChangedAt  time.Time          `bson:"passwordChangedAt"`
	PasswordExpiresAt  time.Time          `bson:"passwordExpiresAt"`
	RegistrationStatus string             `bson:"registrationStatus"`
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

	doc := mongoUser{
		Username:           u.Username,
		FirstName:          u.FirstName,
		LastName:           u.LastName,
		Email:              u.Email,
		PasswordHash:       u.PasswordHash,
		Verified:           false,
		RegistrationStatus: models.RegistrationPending,
		PasswordChangedAt:  time.Now(),
		PasswordExpiresAt:  time.Now().Add(models.PasswordMaxAge),
	}
	if _, err := s.col.InsertOne(ctx, doc); err != nil {
		return "", err
	}
	s.verificationMap[token] = u.Username
	return token, nil
}

func (s *MongoUserStore) Confirm(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	username, ok := s.verificationMap[token]
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
	delete(s.verificationMap, token)
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
	s.otpMap[code] = otpEntry{Username: username, ExpiresAt: time.Now().Add(10 * time.Minute)}
	return code, nil
}

func (s *MongoUserStore) VerifyOTP(code string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.otpMap[code]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return "", ErrOTPInvalid
	}
	delete(s.otpMap, code)
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
	s.resetMap[token] = resetEntry{
		Username:  u.Username,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	return token, nil
}

func (s *MongoUserStore) ResetPassword(token, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.resetMap[token]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return ErrResetInvalid
	}
	delete(s.resetMap, token)

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
