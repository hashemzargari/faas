package meta

import (
	"context"
	"errors"
	"time"

	"github.com/fass-storage/fass/internal/contract"
	"github.com/fass-storage/fass/internal/coord/coerr"
	"github.com/fass-storage/fass/internal/storage"
)

var spaceProjects = []byte("projects")

// Project is the tenant's isolation unit for buckets, access keys and policies
// (docs/04 §5.1). The embedded engine currently stores it only for the console
// and bootstrap; the data path carries tenant_id/project_id on every record.
type Project struct {
	ProjectID contract.ProjectID `json:"project_id"`
	TenantID  contract.TenantID  `json:"tenant_id"`
	Name      string             `json:"name"`
	CreatedAt time.Time          `json:"created_at"`
}

// PutProject creates or replaces a project. CreatedAt is preserved across
// idempotent re-registration.
func (s *Service) PutProject(ctx context.Context, p Project) error {
	if p.ProjectID == "" {
		return coerr.Invalidf("project_id is required")
	}
	if p.TenantID == "" || p.Name == "" {
		return coerr.Invalidf("tenant_id and project name are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(ctx, func(tx *storage.WriteTx) error {
		if existing, err := storage.GetJSON[Project](tx, spaceProjects, []byte(p.ProjectID)); err == nil {
			p.CreatedAt = existing.CreatedAt
		} else if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = s.now().UTC()
		}
		return storage.PutJSON(tx, spaceProjects, []byte(p.ProjectID), p)
	})
}

// GetProject returns a project record.
func (s *Service) GetProject(ctx context.Context, projectID contract.ProjectID) (Project, error) {
	var out Project
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		rec, err := storage.GetJSON[Project](tx, spaceProjects, []byte(projectID))
		if errors.Is(err, storage.ErrNotFound) {
			return coerr.E(404, "NoSuchProject", "project %q does not exist", projectID)
		}
		if err != nil {
			return err
		}
		out = rec
		return nil
	})
	return out, err
}

// ListProjects returns projects, filtered by tenant when non-empty.
func (s *Service) ListProjects(ctx context.Context, tenant contract.TenantID) ([]Project, error) {
	out := []Project{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := s.db.View(ctx, func(tx *storage.ReadTx) error {
		return storage.ScanJSON[Project](tx, spaceProjects, nil, func(_ []byte, p Project) error {
			if tenant != "" && p.TenantID != tenant {
				return nil
			}
			out = append(out, p)
			return nil
		})
	})
	return out, err
}
