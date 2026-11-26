package src

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// LOCAL PATCH (ovpn-admin), fifth modification: --password-stdin. A password given as --password=<value> sits in
// /proc/<pid>/cmdline and in "ps" for as long as the command runs, readable by every local user. The commands
// create, change-password and auth now take --password-stdin: the password is one line on stdin. --password keeps
// working and prints one line on stderr saying it is deprecated. The 72 byte bcrypt guard (errPasswordTooLong) sits
// in CreateUser and ChangeUserPassword, so it covers both ways in.

// maxPasswordLine bounds what is read from stdin: a line longer than this is refused instead of buffered.
const maxPasswordLine = 4096

// PasswordFlagDeprecation is the one line printed on stderr when --password is used.
const PasswordFlagDeprecation = "openvpn-user: warning: --password is deprecated, the password is visible in the process list; use --password-stdin"

var (
	errPasswordBoth    = errors.New("--password and --password-stdin cannot be used together")
	errPasswordMissing = errors.New("a password is required: use --password-stdin (or the deprecated --password)")
	errPasswordNoLine  = errors.New("--password-stdin: no password line on stdin")
	errPasswordEmpty   = errors.New("--password-stdin: the password line is empty")
	errPasswordLong    = fmt.Errorf("--password-stdin: the password line is longer than %d bytes", maxPasswordLine)
)

// ReadPasswordLine reads one line from in and returns it without its line end (LF or CRLF). The rest of the input is
// not read. A line without a final line end is accepted; no input at all is an error.
func ReadPasswordLine(in io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(in, maxPasswordLine+2))
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("--password-stdin: %w", err)
	}
	if line == "" && err == io.EOF {
		return "", errPasswordNoLine
	}
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
	}
	if len(line) > maxPasswordLine {
		return "", errPasswordLong
	}
	return line, nil
}

// ResolvePassword returns the password of a command. given is the value of --password and givenSet tells whether the
// flag was on the command line at all (an empty --password= counts as given); fromStdin is --password-stdin. When
// both are used it is an error. --password prints PasswordFlagDeprecation on warn. With neither, an error when
// required, otherwise the empty string. allowEmptyStdin is for auth, which answers an empty password itself.
func ResolvePassword(given string, givenSet, fromStdin bool, stdin io.Reader, warn io.Writer, required, allowEmptyStdin bool) (string, error) {
	switch {
	case givenSet && fromStdin:
		return "", errPasswordBoth
	case fromStdin:
		pw, err := ReadPasswordLine(stdin)
		if err != nil {
			return "", err
		}
		if pw == "" && !allowEmptyStdin {
			return "", errPasswordEmpty
		}
		return pw, nil
	case givenSet:
		fmt.Fprintln(warn, PasswordFlagDeprecation)
		return given, nil
	case required:
		return "", errPasswordMissing
	}
	return "", nil
}
