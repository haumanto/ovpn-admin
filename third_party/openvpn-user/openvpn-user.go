package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pashcovich/openvpn-user/src"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

const (
	version = "1.0.9"
)

var (
	dbPath = kingpin.Flag("db.path", "path do openvpn-user db").Default("./openvpn-user.db").String()

	dbInitCommand    = kingpin.Command("db-init", "Init db.")
	dbMigrateCommand = kingpin.Command("db-migrate", "STUB: Migrate db.")

	createCommand             = kingpin.Command("create", "Create user.")
	createCommandUserFlag     = createCommand.Flag("user", "Username.").Required().String()
	createCommandPasswordFlag = createCommand.Flag("password", "Password (deprecated: visible in the process list, use --password-stdin).").Action(markSet(&createPasswordSet)).String()
	// LOCAL PATCH (ovpn-admin), fifth modification: --password-stdin, see src/password_input.go.
	createCommandPasswordStdinFlag = createCommand.Flag("password-stdin", "Read the password as one line from stdin.").Default("false").Bool()

	deleteCommand              = kingpin.Command("delete", "Delete user.")
	deleteCommandUserForceFlag = deleteCommand.Flag("force", "delete from db.").Short('f').Default("false").Bool()
	deleteCommandUserFlag      = deleteCommand.Flag("user", "Username.").Short('u').Required().String()

	revokeCommand         = kingpin.Command("revoke", "Revoke user.")
	revokeCommandUserFlag = revokeCommand.Flag("user", "Username.").Short('u').Required().String()

	restoreCommand         = kingpin.Command("restore", "Restore user.")
	restoreCommandUserFlag = restoreCommand.Flag("user", "Username.").Short('u').Required().String()

	listCommand        = kingpin.Command("list", "List active users.")
	listCommandAllFlag = listCommand.Flag("all", "Show all users include revoked and deleted.").Short('a').Default("false").Bool()

	checkCommand         = kingpin.Command("check", "check user existent.")
	checkCommandUserFlag = checkCommand.Flag("user", "Username.").Short('u').Required().String()

	authCommand                  = kingpin.Command("auth", "Auth user.")
	authCommandUserFlag          = authCommand.Flag("user", "Username.").Short('u').Required().String()
	authCommandPasswordFlag      = authCommand.Flag("password", "Password (deprecated: visible in the process list, use --password-stdin).").Short('p').Action(markSet(&authPasswordSet)).String()
	authCommandPasswordStdinFlag = authCommand.Flag("password-stdin", "Read the password as one line from stdin.").Default("false").Bool()
	authCommandTotpFlag          = authCommand.Flag("totp", "TOTP code.").Short('t').String()

	changePasswordCommand                  = kingpin.Command("change-password", "Change password")
	changePasswordCommandUserFlag          = changePasswordCommand.Flag("user", "Username.").Short('u').Required().String()
	changePasswordCommandPasswordFlag      = changePasswordCommand.Flag("password", "Password (deprecated: visible in the process list, use --password-stdin).").Short('p').Action(markSet(&changePasswordSet)).String()
	changePasswordCommandPasswordStdinFlag = changePasswordCommand.Flag("password-stdin", "Read the password as one line from stdin.").Default("false").Bool()

	updateSecretCommand           = kingpin.Command("update-secret", "update OTP secret")
	updateSecretCommandUserFlag   = updateSecretCommand.Flag("user", "Username.").Short('u').Required().String()
	updateSecretCommandSecretFlag = updateSecretCommand.Flag("secret", "Secret.").Short('s').Default("generate").String()

	registerAppCommand         = kingpin.Command("register-app", "register 2FA application")
	registerAppCommandUserFlag = registerAppCommand.Flag("user", "Username.").Short('u').Required().String()
	registerAppCommandTotpFlag = registerAppCommand.Flag("totp", "TOTP.").Short('t').Required().String()

	resetAppCommand         = kingpin.Command("reset-app", "register 2FA application")
	resetAppCommandUserFlag = resetAppCommand.Flag("user", "Username.").Short('u').Required().String()

	checkAppCommand         = kingpin.Command("check-app", "check 2FA application")
	checkAppCommandUserFlag = checkAppCommand.Flag("user", "Username.").Short('u').Required().String()

	getSecretCommand         = kingpin.Command("get-secret", "get OTP secret")
	getSecretCommandUserFlag = getSecretCommand.Flag("user", "Username.").Short('u').Required().String()

	// LOCAL PATCH (ovpn-admin), fourth modification: the re-hash spool, see src/rehash_spool.go. Run as the user that may write the database.
	rehashApplyCommand          = kingpin.Command("rehash-apply", "Store the password hashes that logins of a user who cannot write the database left in the spool directory.")
	rehashApplyCommandSpoolFlag = rehashApplyCommand.Flag("spool", "Spool directory, default <db.path>.rehash.").String()
)

// LOCAL PATCH (ovpn-admin), fifth modification: whether --password was on the command line (an empty --password= counts).
var createPasswordSet, authPasswordSet, changePasswordSet bool

func markSet(b *bool) func(*kingpin.ParseContext) error {
	return func(*kingpin.ParseContext) error { *b = true; return nil }
}

// passwordOrFatal resolves --password / --password-stdin of a command, see src.ResolvePassword.
func passwordOrFatal(given string, givenSet, fromStdin, required, allowEmptyStdin bool) string {
	pw, err := src.ResolvePassword(given, givenSet, fromStdin, os.Stdin, os.Stderr, required, allowEmptyStdin)
	if err != nil {
		kingpin.Fatalf(err.Error())
	}
	return pw
}

func main() {

	args := kingpin.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		kingpin.Fatalf(err.Error())
	}
	defer func(db *sql.DB) {
		err = db.Close()
		if err != nil {
			kingpin.Fatalf(err.Error())
		}
	}(db)

	openvpnUser := src.OpenvpnUser{Database: db, SpoolDir: src.SpoolDirFor(*dbPath)}

	kingpin.Version(version).VersionFlag.Short('v')

	switch args {
	case createCommand.FullCommand():
		wrap(openvpnUser.CreateUser(*createCommandUserFlag,
			passwordOrFatal(*createCommandPasswordFlag, createPasswordSet, *createCommandPasswordStdinFlag, true, false)))
	case deleteCommand.FullCommand():
		wrap(openvpnUser.DeleteUser(*deleteCommandUserFlag, *deleteCommandUserForceFlag))
	case revokeCommand.FullCommand():
		wrap(openvpnUser.RevokedUser(*revokeCommandUserFlag))
	case restoreCommand.FullCommand():
		wrap(openvpnUser.RestoreUser(*restoreCommandUserFlag))
	case listCommand.FullCommand():
		openvpnUser.PrintUsers(*listCommandAllFlag)
	case checkCommand.FullCommand():
		_ = openvpnUser.CheckUserExistent(*checkCommandUserFlag)
	case authCommand.FullCommand():
		authPassword := passwordOrFatal(*authCommandPasswordFlag, authPasswordSet, *authCommandPasswordStdinFlag, false, true)
		provideAuthType := 0
		if authPassword != "" {
			provideAuthType += 1
		}
		if *authCommandTotpFlag != "" {
			provideAuthType += 1
		}
		if provideAuthType == 1 {
			authSuccessful, authErr := openvpnUser.AuthUser(*authCommandUserFlag, authPassword, *authCommandTotpFlag)
			if authErr != nil {
				kingpin.Fatalf(authErr.Error())
			} else if authSuccessful {
				fmt.Println("Authorization successful")
			} else {
				fmt.Println("Authorization failed")
			}

		} else {
			fmt.Println("Please provide only one type of auth flag")
			os.Exit(1)
		}
	case changePasswordCommand.FullCommand():
		wrap(openvpnUser.ChangeUserPassword(*changePasswordCommandUserFlag,
			passwordOrFatal(*changePasswordCommandPasswordFlag, changePasswordSet, *changePasswordCommandPasswordStdinFlag, true, false)))
	case updateSecretCommand.FullCommand():
		wrap(openvpnUser.RegisterOtpSecret(*updateSecretCommandUserFlag, *updateSecretCommandSecretFlag))
	case registerAppCommand.FullCommand():
		wrap(openvpnUser.RegisterOtpApplication(*registerAppCommandUserFlag, *registerAppCommandTotpFlag))
	case resetAppCommand.FullCommand():
		wrap(openvpnUser.ResetOtpApplication(*resetAppCommandUserFlag))
	case checkAppCommand.FullCommand():
		appConfigured, appErr := openvpnUser.IsSecondFactorEnabled(*checkAppCommandUserFlag)
		if appErr != nil {
			kingpin.Fatalf(appErr.Error())
		} else if appConfigured {
			fmt.Println("App configured")
		} else {
			fmt.Println("App not configured yet")
		}
	case getSecretCommand.FullCommand():
		wrap(openvpnUser.GetUserOtpSecret(*getSecretCommandUserFlag))

	case rehashApplyCommand.FullCommand():
		if *rehashApplyCommandSpoolFlag != "" {
			openvpnUser.SpoolDir = *rehashApplyCommandSpoolFlag
		}
		results, err := openvpnUser.ApplySpool()
		src.PrintSpoolResults(os.Stdout, results)
		if err != nil {
			kingpin.Fatalf(err.Error())
		}
	case dbInitCommand.FullCommand():
		openvpnUser.InitDb()
	case dbMigrateCommand.FullCommand():
		openvpnUser.MigrateDb()
	}
}

func wrap(msg string, err error) {
	if err != nil {
		kingpin.Fatalf(err.Error())
	} else {
		fmt.Println(msg)
	}
}
