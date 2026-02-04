// Copyright 2024 The Obsidian Authors
// This file is part of the Obsidian library.

package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// Manager manages database backups
type Manager struct {
	dataDir    string
	backupDir  string
	maxBackups int
}

// New creates a new backup manager
func New(dataDir string, maxBackups int) *Manager {
	return &Manager{
		dataDir:    dataDir,
		backupDir:  filepath.Join(dataDir, "backups"),
		maxBackups: maxBackups,
	}
}

// Create creates a backup of the database
func (m *Manager) Create(name string) (string, error) {
	// Create backup directory
	if err := os.MkdirAll(m.backupDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename with timestamp
	if name == "" {
		name = fmt.Sprintf("backup-%s", time.Now().Format("2006-01-02-150405"))
	}
	backupPath := filepath.Join(m.backupDir, name+".tar.gz")

	log.Info("Creating database backup", "path", backupPath)

	// Create backup file
	file, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()

	// Create gzip writer
	gz := gzip.NewWriter(file)
	defer gz.Close()

	// Create tar writer
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// Archive database files
	if err := m.archiveDirectory(tw, filepath.Join(m.dataDir, "chaindata"), "chaindata"); err != nil {
		os.Remove(backupPath)
		return "", fmt.Errorf("failed to archive database: %w", err)
	}

	if err := m.archiveDirectory(tw, filepath.Join(m.dataDir, "keystore"), "keystore"); err != nil {
		// Keystore backup is optional
		log.Warn("Failed to archive keystore", "err", err)
	}

	log.Info("Database backup completed", "path", backupPath)

	// Cleanup old backups
	if err := m.cleanupOldBackups(); err != nil {
		log.Warn("Failed to cleanup old backups", "err", err)
	}

	return backupPath, nil
}

// Restore restores a database from backup
func (m *Manager) Restore(backupPath string) error {
	log.Info("Restoring database from backup", "path", backupPath)

	// Open backup file
	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	// Create tar reader
	tr := tar.NewReader(gr)

	// Extract files
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Create target path
		targetPath := filepath.Join(m.dataDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(targetPath, 0700); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}

			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			outFile.Close()

			// Set permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set permissions: %w", err)
			}
		}
	}

	log.Info("Database restore completed", "path", backupPath)
	return nil
}

// List lists available backups
func (m *Manager) List() ([]os.FileInfo, error) {
	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(m.backupDir, 0700); err != nil {
		return nil, err
	}

	files, err := os.ReadDir(m.backupDir)
	if err != nil {
		return nil, err
	}

	var result []os.FileInfo
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".gz" {
			info, err := f.Info()
			if err != nil {
				continue
			}
			result = append(result, info)
		}
	}

	return result, nil
}

// Delete deletes a backup
func (m *Manager) Delete(filename string) error {
	backupPath := filepath.Join(m.backupDir, filename)

	// Safety check - only allow deletion from backup directory
	if !strings.HasPrefix(backupPath, m.backupDir) {
		return fmt.Errorf("invalid backup path")
	}

	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}

	log.Info("Backup deleted", "file", filename)
	return nil
}

// archiveDirectory adds a directory to the tar archive
func (m *Manager) archiveDirectory(tw *tar.Writer, srcDir, tarDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// Create tar entry
		tarPath := filepath.Join(tarDir, relPath)
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return err
		}
		header.Name = tarPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tw, file); err != nil {
			return err
		}

		return nil
	})
}

// cleanupOldBackups removes old backups exceeding maxBackups
func (m *Manager) cleanupOldBackups() error {
	files, err := m.List()
	if err != nil {
		return err
	}

	if len(files) <= m.maxBackups {
		return nil
	}

	// Sort by modification time
	// Delete oldest backups
	for i := 0; i < len(files)-m.maxBackups; i++ {
		filename := files[i].Name()
		if err := m.Delete(filename); err != nil {
			log.Warn("Failed to delete old backup", "file", filename, "err", err)
		}
	}

	return nil
}
