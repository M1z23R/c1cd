package logs

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Logger provides application-wide logging to both terminal and file
type Logger struct {
	logger  *log.Logger
	file    *os.File
	mu      sync.Mutex
}

var (
	appLogger     *Logger
	appLoggerOnce sync.Once
)

// GetLogger returns the global application logger instance
func GetLogger() *Logger {
	appLoggerOnce.Do(func() {
		// Use ~/.cache/c1cd/logs for storing logs
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "/tmp"
		}
		logDir := filepath.Join(homeDir, ".cache", "c1cd", "logs")

		// Create logs directory if it doesn't exist
		os.MkdirAll(logDir, 0755)

		logPath := filepath.Join(logDir, "c1cd.log")

		// Open log file in append mode
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Fall back to terminal-only logging
			appLogger = &Logger{
				logger: log.New(os.Stdout, "", log.LstdFlags),
			}
			return
		}

		// Create MultiWriter to write to both terminal and file
		multiWriter := io.MultiWriter(os.Stdout, file)
		appLogger = &Logger{
			logger: log.New(multiWriter, "", log.LstdFlags),
			file:   file,
		}
	})
	return appLogger
}

// Println logs a message (similar to fmt.Println)
func (l *Logger) Println(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Println(v...)
}

// Printf logs a formatted message (similar to fmt.Printf)
func (l *Logger) Printf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Printf(format, v...)
}

// Print logs a message without newline
func (l *Logger) Print(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logger.Print(v...)
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// LogPath returns the path to the log file
func (l *Logger) LogPath() string {
	if l.file != nil {
		return l.file.Name()
	}
	return ""
}

// JobLog represents a stored job execution log
type JobLog struct {
	ID          string
	ProjectName string
	CommitSHA   string
	StartTime   time.Time
	EndTime     *time.Time
	Status      string // "running", "success", "failed"
	LogPath     string
	Writer      io.WriteCloser
}

// LogStore manages job logs
type LogStore struct {
	mu      sync.RWMutex
	logs    map[string]*JobLog
	baseDir string
}

var (
	globalStore *LogStore
	once        sync.Once
)

// GetStore returns the global log store instance
func GetStore() *LogStore {
	once.Do(func() {
		// Use ~/.cache/c1cd/logs for storing logs
		homeDir, err := os.UserHomeDir()
		if err != nil {
			homeDir = "/tmp"
		}
		baseDir := filepath.Join(homeDir, ".cache", "c1cd", "logs")

		globalStore = &LogStore{
			logs:    make(map[string]*JobLog),
			baseDir: baseDir,
		}

		// Create logs directory if it doesn't exist
		os.MkdirAll(baseDir, 0755)
	})
	return globalStore
}

// CreateJob creates a new job log entry and returns its ID
func (s *LogStore) CreateJob(projectName, commitSHA string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobID := uuid.New().String()
	logPath := filepath.Join(s.baseDir, fmt.Sprintf("%s.log", jobID))

	// Create log file
	file, err := os.Create(logPath)
	if err != nil {
		return "", fmt.Errorf("failed to create log file: %w", err)
	}

	job := &JobLog{
		ID:          jobID,
		ProjectName: projectName,
		CommitSHA:   commitSHA,
		StartTime:   time.Now(),
		Status:      "running",
		LogPath:     logPath,
		Writer:      file,
	}

	s.logs[jobID] = job
	return jobID, nil
}

// GetJobWriter returns the writer for a job (for streaming logs)
func (s *LogStore) GetJobWriter(jobID string) (io.Writer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, exists := s.logs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return job.Writer, nil
}

// CompleteJob marks a job as completed and closes the log file
func (s *LogStore) CompleteJob(jobID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, exists := s.logs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	now := time.Now()
	job.EndTime = &now
	job.Status = status

	// Close the writer
	if job.Writer != nil {
		job.Writer.Close()
		job.Writer = nil
	}

	return nil
}

// GetJobLog retrieves the log content for a job
func (s *LogStore) GetJobLog(jobID string) (*JobLog, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, exists := s.logs[jobID]
	if !exists {
		return nil, nil, fmt.Errorf("job not found: %s", jobID)
	}

	// Read the log file
	content, err := os.ReadFile(job.LogPath)
	if err != nil {
		return job, nil, fmt.Errorf("failed to read log file: %w", err)
	}

	return job, content, nil
}

// GetJob retrieves job metadata
func (s *LogStore) GetJob(jobID string) (*JobLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, exists := s.logs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	return job, nil
}

// CleanupOldLogs removes logs older than the specified duration
func (s *LogStore) CleanupOldLogs(maxAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	var toDelete []string

	for jobID, job := range s.logs {
		if job.EndTime != nil && job.EndTime.Before(cutoff) {
			toDelete = append(toDelete, jobID)
		}
	}

	for _, jobID := range toDelete {
		job := s.logs[jobID]

		// Close writer if still open
		if job.Writer != nil {
			job.Writer.Close()
		}

		// Delete log file
		os.Remove(job.LogPath)

		// Remove from map
		delete(s.logs, jobID)
	}

	return nil
}
