package main

import (
	"bufio"
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
	"os"
	"strings"
)

func main() {
	er, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Failed to initialize RBAC enforcer: %v", err)
	}

	e, err := casbin.NewEnforcer("a_model.conf", "a_policy.csv")
	if err != nil {
		log.Fatalf("Failed to initialize ABAC enforcer: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Choose mode: (1) RBAC (2) ABAC (3) Exit")
		mode, _ := reader.ReadString('\n')
		mode = strings.TrimSpace(mode)

		switch mode {
		case "1":
			runRBACCLI(er)
		case "2":
			runABACCLI(e)
		case "3":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid choice, please try again.")
		}
	}
}

func runRBACCLI(e *casbin.Enforcer) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter subject: ")
	sub, _ := reader.ReadString('\n')
	sub = strings.TrimSpace(sub)

	fmt.Print("Enter object: ")
	obj, _ := reader.ReadString('\n')
	obj = strings.TrimSpace(obj)

	fmt.Print("Enter action: ")
	act, _ := reader.ReadString('\n')
	act = strings.TrimSpace(act)

	checkPermissionRBAC(e, sub, obj, act)
}

func runABACCLI(e *casbin.Enforcer) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter subject: ")
	sub, _ := reader.ReadString('\n')
	sub = strings.TrimSpace(sub)

	fmt.Print("Enter object: ")
	obj, _ := reader.ReadString('\n')
	obj = strings.TrimSpace(obj)

	fmt.Print("Enter action: ")
	act, _ := reader.ReadString('\n')
	act = strings.TrimSpace(act)

	fmt.Print("Enter environment attribute (time): ")
	t, _ := reader.ReadString('\n')
	t = strings.TrimSpace(t)

	PermissionABAC(e, sub, obj, act, t)
}

func checkPermissionRBAC(e *casbin.Enforcer, sub, obj, act string) {
	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.Fatalf("Failed to enforce policy: %v", err)
	}

	if ok {
		fmt.Printf("Access granted for %s to %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("Access denied for %s to %s %s\n", sub, act, obj)
	}
}

func PermissionABAC(e *casbin.Enforcer, sub, obj, act, t string) {
	ok, err := e.Enforce(sub, obj, act, t)
	if err != nil {
		log.Fatalf("Failed to enforce policy: %v", err)
	}

	if ok {
		fmt.Printf("Access granted for %s to %s %s at %s %s\n", sub.Role, act, obj.DataType, env.TimeOfDay, env.Location)
	} else {
		fmt.Printf("Access denied for %s to %s %s at %s %s\n", sub.Role, act, obj.DataType, env.TimeOfDay, env.Location)
	}
}

