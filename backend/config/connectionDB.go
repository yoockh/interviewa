package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectionDb() *gorm.DB {
	if err := godotenv.Load(); err != nil {
		log.Printf("error load env %s", err)
	}

	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // Disable prepared statements completely
	}), &gorm.Config{
		PrepareStmt: false,
	})
	if err != nil {
		log.Printf("error connect to database %s", err)
	}

	fmt.Println("success connect to db")
	return db
}
