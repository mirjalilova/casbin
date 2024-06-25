package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/casbin/casbin/v2"
)

type Subject struct {
	Role string
}

type Object struct {
	Type string
}

type Env struct {
	Time         string
	FaceID       string
	EnoughPoints string
	PaymentDone  string
	LessonNumber string
}

type Action struct {
	Action string
}

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
		fmt.Println("[1] RBAC [2] ABAC [0] Exit")
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
			fmt.Println("Invalid choice, please try again")
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

	fmt.Print("Enter environment attribute Time: ")
	t, _ := reader.ReadString('\n')
	t = strings.TrimSpace(t)

	fmt.Print("Enter environment attribute FaceID: ")
	face_id, _ := reader.ReadString('\n')
	face_id = strings.TrimSpace(face_id)

	fmt.Print("Enter environment attribute EnoughPoints: ")
	point, _ := reader.ReadString('\n')
	point = strings.TrimSpace(point)

	fmt.Print("Enter environment attribute PaymentDone: ")
	payment, _ := reader.ReadString('\n')
	payment = strings.TrimSpace(payment)

	fmt.Print("Enter environment attribute LessonNumber: ")
	lesson, _ := reader.ReadString('\n')
	lesson = strings.TrimSpace(lesson)

	env := Env{
		Time:         t,
        FaceID:       face_id,
        EnoughPoints: point,
        PaymentDone:  payment,
        LessonNumber: lesson,
    }

	PermissionABAC(e, sub, obj, act, env)
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

func PermissionABAC(e *casbin.Enforcer, sub, obj, act string, env Env) {
	ok, err := e.Enforce(sub, obj, act, env.Time, env.FaceID, env.EnoughPoints, env.PaymentDone, env.LessonNumber)
	if err != nil {
		log.Fatalf("Failed to enforce policy: %v", err)
	}

	if ok {
		fmt.Printf("Access granted for %s to %s %s at %s\n", sub, act, obj, env)
	} else {
		fmt.Printf("Access denied for %s to %s %s at %s\n", sub, act, obj, env)
	}
}
