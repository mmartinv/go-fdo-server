// SPDX-FileCopyrightText: (C) 2026 Red Hat Inc.
// SPDX-License-Identifier: Apache 2.0

package state

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        string    `gorm:"type:varchar(36);primaryKey"`
	Name      string    `gorm:"type:varchar(255);not null"`
	Email     string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	Active    bool      `gorm:"type:boolean;not null;default:true"`
	CreatedAt time.Time `gorm:"autoCreateTime:milli"`
	UpdatedAt time.Time `gorm:"autoUpdateTime:milli"`
}

func (User) TableName() string { return "users" }

func CreateUser(ctx context.Context, db *gorm.DB, name, email string) (*User, error) {
	user := &User{
		ID:     uuid.New().String(),
		Name:   name,
		Email:  email,
		Active: true,
	}
	if err := db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

func GetUserByID(ctx context.Context, db *gorm.DB, id string) (*User, error) {
	var user User
	if err := db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return &user, nil
}

func UserCount(ctx context.Context, db *gorm.DB) (int64, error) {
	var count int64
	if err := db.WithContext(ctx).Model(&User{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}
