package main
 
import (
    "net/http"
    "net/url"
    "encoding/base64"
    "encoding/json"
    "io/ioutil"
    "io"
	"log"
	"strconv"
	"fmt"
)

func newGoComment() (*GoComment,error){
	bytes, err := ioutil.ReadFile("C:/dev/workspaces/go/src/mikesu.net/gocomment/gocomment.conf")
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	var goComment GoComment
	err = json.Unmarshal(bytes, &goComment)
    if err != nil {
       log.Fatal(err)
       return nil, err
    }
    return &goComment, nil
}

func token(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "token=abc")
}

type GoComment struct{
	Client_id, Client_secret string
	Port int
}

func (goComment *GoComment)  Redirect(w http.ResponseWriter, req *http.Request) {
	encoded_url := req.FormValue("url")
	decoded_url, err := base64.StdEncoding.DecodeString(encoded_url)
	if err != nil {
		log.Fatal(err)
		io.WriteString(w, err.Error())
		return
	}
	code := req.FormValue("code")
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", goComment.Client_id)
	data.Set("client_secret", goComment.Client_secret)
	//resp, err := http.Post("https://github.com/login/oauth/access_token",data)
	resp, err := http.PostForm("http://localhost:"+strconv.Itoa(goComment.Port) +"/token", data)
	if err != nil {
		log.Fatal(err)
		io.WriteString(w, err.Error())
		return
	}
	token, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		io.WriteString(w, err.Error())
		return
	}
	redirect_url := string(decoded_url) + "?" + string(token)
	fmt.Println(strconv.Itoa(goComment.Port))
	http.Redirect(w,req,redirect_url,302)
}
 
func main() {
	goComment,err := newGoComment()
	if err != nil {
		log.Fatal(err)
		return
	}
	http.HandleFunc("/token", token)
    http.HandleFunc("/redirect", goComment.Redirect)
    fmt.Println(strconv.Itoa(goComment.Port))
    http.ListenAndServe(":"+strconv.Itoa(goComment.Port), nil)
}