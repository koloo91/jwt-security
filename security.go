package jwtsecurity

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	refreshTokenKey = "refresh_token"
	accessTokenKey  = "access_token"
)

type RefreshTokenClaim struct {
	jwt.StandardClaims
	Id string `json:"id"`
}

type AccessTokenClaim struct {
	jwt.StandardClaims
	Id      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

func GetAccessTokenFromContext(ctx *gin.Context) AccessTokenClaim {
	value, _ := ctx.Get(accessTokenKey)
	accessTokenClaim := value.(AccessTokenClaim)
	return accessTokenClaim
}

func JwtMiddleware(jwtKey []byte) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeaderValue := ctx.GetHeader("Authorization")
		if len(authorizationHeaderValue) == 0 {
			log.Println("missing authorization header")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorVo{Message: "missing authorization header"})
			return
		}

		accessTokenClaims := AccessTokenClaim{}

		tokenString := strings.ReplaceAll(authorizationHeaderValue, "Bearer ", "")
		token, err := jwt.ParseWithClaims(tokenString, &accessTokenClaims, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				log.Printf("unexpected signing method: %v", token.Header["alg"])
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return jwtKey, nil
		})

		if err != nil {
			log.Println("error parsing token")
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, ErrorVo{Message: "unexpected error"})
			return
		}

		if !token.Valid {
			log.Println("invalid token")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorVo{Message: "invalid token"})
			return
		}

		if time.Unix(accessTokenClaims.ExpiresAt, 0).Sub(time.Now()).Seconds() <= 0 {
			log.Println("token expired")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ErrorVo{Message: "token expired"})
			return
		}

		ctx.Set(accessTokenKey, accessTokenClaims)

		ctx.Next()
	}
}
