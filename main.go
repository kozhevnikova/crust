package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/securecookie"
	. "github.com/logrusorgru/aurora"
	"github.com/naoina/toml"
)

var uploadT *template.Template
var loginT *template.Template
var registrationT *template.Template

type router struct {
	db *sql.DB
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type storeUserData struct {
	userid   int
	username string
}

type Config struct {
	Database struct {
		User     string
		Password string
		Name     string
		Host     string
	}
}

const cookieName = "mycookie"

var hashKey = []byte(securecookie.GenerateRandomKey(32))
var blockKey = []byte(securecookie.GenerateRandomKey(32))
var sc = securecookie.New(hashKey, blockKey)

func init() {
	uploadT = template.Must(template.ParseFiles("./templates/upload.html",
		"./templates/nav.html"))

	loginT = template.Must(template.ParseFiles("./templates/login.html"))
	registrationT = template.Must(template.ParseFiles("./templates/singup.html"))
}

func parseConfig() (Config, error) {
	var config Config
	f, err := os.Open("config.toml")
	if err != nil {
		return config, err
	}
	defer f.Close()
	if err := toml.NewDecoder(f).Decode(&config); err != nil {
		return config, err
	}
	return config, err
}

func connectToPostgresql(config Config) (*sql.DB, error) {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s host=%s sslmode=disable",
		config.Database.User, config.Database.Password,
		config.Database.Name, config.Database.Host)
	db, err := sql.Open("postgres", dbinfo)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return db, nil
}

func createConnection() (*sql.DB, error) {
	config, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR parseConfig >", err)
		return nil, err
	}
	db, err := connectToPostgresql(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR connectToPostgresql >", err)
		return nil, err
	}
	return db, nil
}

func hashPassword(password string) (string, error) {
	bytesPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(bytesPassword), nil
}

func checkPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func (user *storeUserData) SetCookieValues(w http.ResponseWriter) error {
	value := map[string]string{
		"username": user.username,
		"userID":   strconv.Itoa(user.userid),
	}
	if encoded, err := sc.Encode(cookieName, value); err == nil {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    encoded,
			Path:     "/",
			HttpOnly: true,
		}
		if err != nil {
			return err
		}
		http.SetCookie(w, cookie)
	}
	return nil
}

func readCookies(r *http.Request) (int, string, error) {
	var UserID int
	var Username string

	if cookie, err := r.Cookie(cookieName); err == nil {
		value := make(map[string]string)
		if err = sc.Decode(cookieName, cookie.Value, &value); err == nil {
			Username = value["username"]
			UserID, err = strconv.Atoi(value["userID"])
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR readcookies >", err)
				return 0, "", err
			}
		}
	} else {
		return 0, "", err
	}
	return UserID, Username, nil
}

func checkUsersCookie(userid int, username string) bool {
	if userid == 0 || username == "" {
		return false
	}
	return true
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	userid, username, err := readCookies(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR handle drive page read cookie >",
			Red(err))
	}

	if ok := checkUsersCookie(userid, username); ok == false {
		w.WriteHeader(http.StatusUnauthorized)

		err := loginT.Execute(w, r)
		if err != nil {
			fmt.Fprintln(w, http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, "/drive", 302)
	}
}

func handleRegistrationPage(w http.ResponseWriter, r *http.Request) {
	userid, username, err := readCookies(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR handle registation page read cookie >",
			Red(err))
	}

	if ok := checkUsersCookie(userid, username); ok == false {
		w.WriteHeader(http.StatusUnauthorized)

		err := registrationT.Execute(w, r)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR handleRegistrationPage template >",
				Red(err))

			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, "/drive", 302)
	}
}

func handleDrivePage(w http.ResponseWriter, r *http.Request) {
	userid, username, err := readCookies(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR handle drive page read cookie >",
			Red(err))
	}

	if ok := checkUsersCookie(userid, username); ok == true {
		files, err := getFiles(userid, username)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR getFiles >", Red(err))
			w.WriteHeader(http.StatusNotFound)
		}
		err = uploadT.Execute(w, files)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR template upload >", Red(err))
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
	}
}

func (router *router) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var u User

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR Login json >", Red(err))
	}

	defer r.Body.Close()

	if u.Password != "" && u.Username != "" {
		newUser := template.HTMLEscapeString(u.Username)
		newPassword := template.HTMLEscapeString(u.Password)

		var returnuserid int
		var returnusername string
		var returnpassword string

		err = router.db.QueryRow(
			`SELECT
						userid,
						username,
						password FROM Users WHERE username = $1 `, newUser).Scan(
			&returnuserid,
			&returnusername,
			&returnpassword)

		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
		} else if err == nil && checkPasswordHash(newPassword, returnpassword) {
			user := &storeUserData{
				userid:   returnuserid,
				username: returnusername,
			}
			user.SetCookieValues(w)
			w.WriteHeader(http.StatusAccepted)
		} else if err == sql.ErrConnDone {
			w.WriteHeader(http.StatusInternalServerError)
		} else if err == sql.ErrTxDone {
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:   "mycookie",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", 302)
}

func (router *router) Singup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var u User

	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR Singup json>", Red(err))
	}
	defer r.Body.Close()

	if u.Username != "" || u.Username != "" {
		newUser := template.HTMLEscapeString(u.Username)
		newPassword := template.HTMLEscapeString(u.Password)

		result, err := router.db.Exec(`
			SELECT username FROM users WHERE username =$1`, newUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR singup get result >", Red(err))
			w.WriteHeader(http.StatusInternalServerError)
		}

		count, err := result.RowsAffected()
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR singup get result >", Red(err))
			w.WriteHeader(http.StatusInternalServerError)
		}

		if count == 0 {
			hashedPassword, err := hashPassword(newPassword)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ERROR singup hash password >",
					Red(err))

				w.WriteHeader(http.StatusInternalServerError)
			}

			var userid int
			err = router.db.QueryRow(
				`INSERT INTO Users(Username,Password) VALUES($1,$2) RETURNING userid`,
				newUser, hashedPassword).Scan(&userid)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(os.Stderr, "ERROR singup create user>", Red(err))
			} else {
				err = createDir(userid, newUser)
				if err != nil {
					fmt.Fprintln(os.Stderr, "ERROR handle registation page create dir >",
						Red(err))
					w.WriteHeader(http.StatusInternalServerError)
				}

				w.WriteHeader(http.StatusCreated)
			}
		} else if err == sql.ErrConnDone {
			w.WriteHeader(http.StatusInternalServerError)
		} else if err == sql.ErrTxDone {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusConflict)
		}
	} else {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
}

func createDir(userid int, name string) error {
	id := strconv.Itoa(userid)
	err := os.MkdirAll("./"+id+"/"+name+"/", os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

func getFiles(userid int, name string) ([]string, error) {
	var files []string
	id := strconv.Itoa(userid)
	all, err := ioutil.ReadDir("./" + id + "/" + name + "/")
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		files = append(files, f.Name())
	}
	return files, nil
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	file, handle, err := r.FormFile("file")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR uploadFile >", Red(err))
		w.WriteHeader(http.StatusBadRequest)
	}
	saveFile(w, r, file, handle)
	defer file.Close()
}

func saveFile(
	w http.ResponseWriter, r *http.Request, file multipart.File,
	handle *multipart.FileHeader) {

	userid, name, err := readCookies(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR saveFile read cookie >", Red(err))
		w.WriteHeader(http.StatusBadRequest)
	}
	id := strconv.Itoa(userid)

	data, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR saveFile >", Red(err))
		w.WriteHeader(http.StatusInternalServerError)
	}

	err = ioutil.WriteFile("./"+id+"/"+name+"/"+handle.Filename, data, 0666)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR saveFile >", Red(err))
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		fmt.Fprintf(os.Stdout, "File %s uploaded successfully",
			Green(handle.Filename))
		http.Redirect(w, r, "/drive", 302)
	}
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	userid, name, err := readCookies(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR handle drive page read cookie >",
			Red(err))

		w.WriteHeader(http.StatusBadRequest)
	}
	if ok := checkUsersCookie(userid, name); ok == true {
		fileName := r.FormValue("filename")

		id := strconv.Itoa(userid)

		path := "./" + id + "/" + name + "/" + fileName
		newpath := filepath.Clean(path)

		err := os.Remove(newpath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR deleteFile > ", Red(err))
			w.WriteHeader(http.StatusInternalServerError)
		}

		http.Redirect(w, r, "/drive", 302)
	} else {
		http.Redirect(w, r, "/", http.StatusUnauthorized)
	}
}

func (router *router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	path := r.URL.Path

	switch {
	case method == "GET" && path == "/":
		handleLoginPage(w, r)
	case method == "POST" && path == "/login":
		router.Login(w, r)
	case method == "GET" && path == "/registration":
		handleRegistrationPage(w, r)
	case method == "POST" && path == "/singup":
		router.Singup(w, r)
	case method == "GET" && path == "/drive":
		handleDrivePage(w, r)
	case method == "POST" && path == "/upload":
		uploadFile(w, r)
	case method == "POST" && path == "/logout":
		logout(w, r)
	case method == "POST" && path == "/delete":
		deleteFile(w, r)
	}
}

func main() {
	fmt.Println("Running server on port 8080")

	db, err := createConnection()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR createConnection >", err)
	}

	router := &router{
		db: db,
	}
	http.ListenAndServe(":8080", router)
}
