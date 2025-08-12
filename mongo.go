package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var sessionCollection *mongo.Collection
var resetCooldownCollection *mongo.Collection

func connectMongo() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("MONGO_URI environment variable not set")
	}

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	sessionCollection = client.Database("LRProject3").Collection("sessions")
	resetCooldownCollection = client.Database("LRProject3").Collection("reset_cooldowns")
	log.Println("Connected to MongoDB and collections initialized")
}

func saveSession(sessionID, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := sessionCollection.InsertOne(ctx, map[string]any{
		"session_id":   sessionID,
		"access_token": token,
		"expires_at":   time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		log.Println("Error saving session:", err)
	}
}

func getSessionToken(sessionID string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result map[string]any
	err := sessionCollection.FindOne(ctx, map[string]any{"session_id": sessionID}).Decode(&result)
	if err != nil {
		log.Println("Error fetching session token:", err)
		return ""
	}
	return result["access_token"].(string)
}

func deleteSession(sessionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := sessionCollection.DeleteOne(ctx, map[string]interface{}{"session_id": sessionID})
	if err != nil {
		log.Println("Error deleting session:", err)
	}
}

// Records and checks cooldown for forgot password per email.
func canRequestPasswordReset(email string) (bool, time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var doc map[string]any
	err := resetCooldownCollection.FindOne(ctx, map[string]any{"email": email}).Decode(&doc)
	if err != nil {
		// Not found or other error: allow request
		return true, time.Time{}
	}
	nextAllowedAt, _ := doc["next_allowed_at"].(time.Time)
	if time.Now().Before(nextAllowedAt) {
		return false, nextAllowedAt
	}
	return true, time.Time{}
}

func markPasswordResetRequested(email string, cooldown time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	next := time.Now().Add(cooldown)
	_, err := resetCooldownCollection.UpdateOne(
		ctx,
		map[string]any{"email": email},
		map[string]any{"$set": map[string]any{"email": email, "next_allowed_at": next}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		log.Println("Error marking password reset cooldown:", err)
	}
}
