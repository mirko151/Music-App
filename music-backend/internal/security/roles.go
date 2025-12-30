package security

// Role konstante
const (
	RoleUnauthenticated = "NK"  // Neautentifikovani korisnik
	RoleAdmin           = "A"   // Administrator
	RoleRegularUser     = "RK"  // Redovan korisnik
)

// RoleHierarchy definiše redosled uloga
var RoleHierarchy = map[string]int{
	RoleUnauthenticated: 0,
	RoleRegularUser:     1,
	RoleAdmin:           2,
}

// HasPermission proverava da li korisnik ima dozvolu
func HasPermission(userRole, requiredRole string) bool {
	userLevel, ok := RoleHierarchy[userRole]
	if !ok {
		return false
	}

	requiredLevel, ok := RoleHierarchy[requiredRole]
	if !ok {
		return false
	}

	return userLevel >= requiredLevel
}

// IsAdmin proverava da li je korisnik admin
func IsAdmin(role string) bool {
	return role == RoleAdmin
}

// IsRegularUser proverava da li je korisnik regularni korisnik
func IsRegularUser(role string) bool {
	return role == RoleRegularUser
}

// IsAuthenticated proverava da li je korisnik autentifikovan
func IsAuthenticated(role string) bool {
	return role == RoleRegularUser || role == RoleAdmin
}
