package database

import (
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

var Redis *redis.Client

func InitRedis(redisURL string) error {
	Redis = redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "",
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Redis.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis not available: %v", err)
		return nil
	}

	log.Println("Connected to Redis")
	return nil
}

func CacheSet(key string, value interface{}, expiration time.Duration) error {
	if Redis == nil {
		return nil
	}
	ctx := context.Background()
	return Redis.Set(ctx, key, value, expiration).Err()
}

func CacheGet(key string) (string, error) {
	if Redis == nil {
		return "", redis.Nil
	}
	ctx := context.Background()
	return Redis.Get(ctx, key).Result()
}

func CacheDelete(key string) error {
	if Redis == nil {
		return nil
	}
	ctx := context.Background()
	return Redis.Del(ctx, key).Err()
}

func CloseRedis() {
	if Redis != nil {
		Redis.Close()
	}
}
