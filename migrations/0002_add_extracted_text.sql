-- Migration to add extracted_text column for full-text search
ALTER TABLE documents ADD COLUMN extracted_text TEXT;
