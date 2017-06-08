package main

import (
	"archive/tar"
	"archive/zip"
	"github.com/nwaples/rardecode"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
)

/* AllowPayload runs the appropriate decompress
   function according to provided extension */
func AllowPayload(r *strings.Reader) (err error) {
	// define list of payload functions to try
	PayloadFuncList := []func(*strings.Reader)error{
		AllowTarPayload,
		AllowZipPayload,
		AllowRarPayload,
	}
	for _, Payload := range PayloadFuncList {
		// seek at the beginning of the stream and try next payload
		if _, err = r.Seek(0, 0); err != nil {
			return err
		}
		// check if payload was recognised and found to be clean
		if err = Payload(r); err == nil {
			break
		}
		// check if payload was recognised and blocked
		if err == EPayloadNotAllowed {
			return err
		}
	}
	return nil
}

/* AllowTarPayload inspects a tar attachment in email message and
   returns true if no filenames have a blacklisted extension */
func AllowTarPayload(r *strings.Reader) error {
	// range over tar files
	reader := tar.NewReader(r)
	for {
		// get next file in archive
		header, err := reader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		// check for blacklisted file name
		FileExt := filepath.Ext(strings.ToLower(header.Name))
		if !AllowFilename(FileExt) {
			return EPayloadNotAllowed
		}
		// check for nested archives
		slurp, err := ioutil.ReadAll(reader)
		if err != nil {
			// silently ignore errors
			continue
		}
		// check if sub-payload contains any blacklisted files
		if err := AllowPayload(strings.NewReader(string(slurp))); err != nil {
			// error, return immediately
			return err
		}
	}
	return nil
}

/* AllowZipPayload inspects a zip attachment in email message and
   returns true if no filenames have a blacklisted extension */
func AllowZipPayload(r *strings.Reader) error {
	reader, err := zip.NewReader(r, int64(r.Len()))
	if err != nil {
		return err
	}
	// range over filenames in zip archive
	for _, f := range reader.File {
		FileExt := filepath.Ext(strings.ToLower(f.Name))
		if !AllowFilename(FileExt) {
			return EPayloadNotAllowed
		}
		// check archive within another achive
		payload, err := f.Open()
		if err != nil {
			// silently ignore errors
			continue
		}
		// read sub-payload
		slurp, err := ioutil.ReadAll(payload)
		// check if sub-payload contains any blacklisted files
		if err := AllowPayload(strings.NewReader(string(slurp))); err != nil {
			// error, return immediately
			return err
		}
	}

	return nil
}

/* AllowRarPayload inspects a rar attachment in email message and
   returns true if no filenames have a blacklisted extension */
func AllowRarPayload(r *strings.Reader) error {
	// make rar file reader object
	rr, err := rardecode.NewReader(r, "")
	if err != nil {
		return err
	}
	// walk files in archive
	for {
		header, err := rr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		// compare current name against blacklisted extensions
		FileExt := filepath.Ext(strings.ToLower(header.Name))
		if !AllowFilename(FileExt) {
			return EPayloadNotAllowed
		}
		// check archive within another achive
		slurp, err := ioutil.ReadAll(rr)
		if err != nil {
			// silently ignore errors
			continue
		}
		// check if sub-payload contains any blacklisted files
		if err := AllowPayload(strings.NewReader(string(slurp))); err != nil {
			// error, return immediately
			return err
		}
	}
	// no blacklisted file, allow
	return nil
}
