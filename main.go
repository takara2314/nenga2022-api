package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"gopkg.in/yaml.v2"
)

type postedUserInfo struct {
	Touchable bool   `json:"touchable"`
	Password  string `json:"password"`
}

type userActivity struct {
	DateTime time.Time
	IP       string
	Device   string
	Browser  string
	ID       int
}

type resData struct {
	Status   string `json:"status"`
	Name     string `json:"name"`
	Greeting string `json:"greeting"`
	ModelUrl string `json:"model_url"`
}

type Config struct {
	PasswordsHashed string `yaml:"PASSWORDS_HASHED"`
	PersonNames     string `yaml:"PERSON_NAMES"`
	Greetings       string `yaml:"GREETINGS"`
	Models          string `yaml:"MODELS"`
}

var passwords []string
var personNames []string
var greetings []string
var models []string

func main() {
	config := Config{}
	s, _ := ioutil.ReadFile("./config.yaml")
	yaml.Unmarshal(s, &config)

	passwords = strings.Split(config.PasswordsHashed, ",")
	personNames = strings.Split(config.PersonNames, ",")
	greetings = strings.Split(config.Greetings, ",")
	models = strings.Split(config.Models, ",")

	router := gin.Default()

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:5500", "https://nenga2022.2314.tk"}
	router.Use(cors.New(corsConfig))

	router.POST("/auth", authPOST)
	router.GET("/models/:name", modelsGET)

	router.Run(":" + os.Getenv("PORT"))
}

// [POST] /auth
func authPOST(c *gin.Context) {
	// POSTされたJSONを受け取り、格納する
	var postedJSON postedUserInfo
	_ = c.MustBindWith(&postedJSON, binding.JSON)

	// JSONにuserPasswordが含まれてなかったら、Bad Request
	if postedJSON.Password == "" {
		c.String(http.StatusBadRequest, "400 Bad Request")
		return
	}

	userInfo := userActivity{
		DateTime: timeDiffConv(time.Now()),
		IP:       c.ClientIP(),
		Device:   getDevice(c.Request.Header.Get("user-agent"), postedJSON.Touchable),
		Browser:  getBrowser(c.Request.Header.Get("user-agent")),
		ID:       -1,
	}

	// JSONの中に含まれるパスワードを、ハッシュ化(SHA-256)して格納
	passHashedBytes := sha256.Sum256([]byte(postedJSON.Password))
	var passHashed string = hex.EncodeToString(passHashedBytes[:])

	// パスワードが一致するなら
	if passIndex := findIndexSliceStr(passwords, passHashed); passIndex != -1 {
		res := resData{
			Status:   "OK",
			Name:     personNames[passIndex],
			Greeting: greetings[passIndex],
			ModelUrl: "https://takaran-nenga2022-api.appspot.com/models/" + models[passIndex],
		}
		c.JSON(http.StatusOK, res)

		// 本人確認できたら、ユーザー情報にそのユーザーのID(インデックス)を代入
		userInfo.ID = passIndex

		fmt.Printf(
			"%sがログインしました。\nID: %d\n時刻: %s\nIPアドレス: %s\nデバイス: %s\nブラウザ: %s\nユーザーエージェント: %s\n",
			personNames[passIndex],
			userInfo.ID,
			userInfo.DateTime.Format("2006年1月2日 15時4分5秒"),
			userInfo.IP,
			userInfo.Device,
			userInfo.Browser,
			c.Request.Header.Get("user-agent"),
		)

		return
	}

	c.JSON(http.StatusUnauthorized, resData{
		Status: "Unauthorized",
	})

	fmt.Printf(
		"ログインを試みたユーザーがいましたが、ブロックしました。\n時刻: %s\nIPアドレス: %s\nデバイス: %s\nブラウザ: %s\nユーザーエージェント: %s\n",
		userInfo.DateTime.Format("2006年1月2日 15時4分5秒"),
		userInfo.IP,
		userInfo.Device,
		userInfo.Browser,
		c.Request.Header.Get("user-agent"),
	)
}

// [GET] /models
func modelsGET(c *gin.Context) {
	name := c.Param("name")
	c.File("models/" + name)
}

// 時差変換をして返す関数
func timeDiffConv(tTime time.Time) (rTime time.Time) {
	// よりUTCらしくする
	rTime = tTime.UTC()

	// UTC → JST
	var jst *time.Location = time.FixedZone("Asia/Tokyo", 9*60*60)
	rTime = rTime.In(jst)

	return
}

// 対象の文字列型スライスから特定の文字列のインデックスを返す
func findIndexSliceStr(targetSlice []string, targetStr string) int {
	for i, str := range targetSlice {
		if targetStr == str {
			return i
		}
	}
	return -1
}
