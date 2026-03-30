package gonnect

// UpDown defines an interface for managing the operational state of a resource.
type UpDown interface {
	// Up activates or brings the resource online.
	Up() error
	// Down deactivates or brings the resource offline.
	Down() error
}
