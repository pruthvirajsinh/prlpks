// prc_mailer
package openpgp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	//"os"
	//	"runtime"
	"github.com/pruthvirajsinh/go-Simap/Simap"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type mailerConf struct {
	host     string
	port     string
	userName string
	password string
	sender   string
	//imap Configs
	imapHost   string
	imapPort   string
	imapFreq   int
	procFolder string //Name of the folder where mails will be moved after processing them.
	ownAddr    string
}

//Get Email Server Configuration from Config File
func GetMailerConf() (mailer mailerConf, err error) {
	//###Mailer Config
	//##mailerHost is the address:port of the smtp server,similarly imap
	//mailerHost="pruthviraj-desktop.hom.prc:587"  # SMTP hostname:port
	//imapHost="pruthviraj-desktop.hom.prc:993" #IMAP hostname:port
	//##mailerUser is the account name through which email will be sent/received
	//mailerUser="prc@mail.hom.prc"
	//#mailerPass is password of the above user
	//mailerPass="nathee"
	//#Frequency in Seconds for checking inbox of above account,if not set then default is 2*60
	//imapFreq=4
	//#Name of the folder where mails will be moved after processing them.
	//procFolder="processed"

	mailer.host = Config().GetStringDefault("authority.mailerHost", "")
	mailer.userName = Config().GetStringDefault("authority.mailerUser", "")
	mailer.password = Config().GetStringDefault("authority.mailerPass", "")
	mailer.sender = Config().GetStringDefault("authority.mailerSender", "")
	//imap Configs
	mailer.imapHost = Config().GetStringDefault("authority.imapHost", "")
	mailer.imapFreq = Config().GetIntDefault("authority.imapFreq", 2)

	if mailer.host == "" || mailer.userName == "" || mailer.password == "" || mailer.sender == "" {
		err = errors.New("mailer config is not valid in config file ")
	}
	mailer.host, mailer.port, err = net.SplitHostPort(mailer.host)
	//imap

	mailer.procFolder = Config().GetStringDefault("authority.procFolder", "processed")

	if mailer.imapHost == "" {
		err = errors.New("imap config is not valid in config file ")
	}
	mailer.imapHost, mailer.imapPort, err = net.SplitHostPort(mailer.imapHost)
	if err != nil {
		return
	}
	//Get Own address from Own Authority
	ownAuth, err1 := GetOwnAuthority()
	if err1 != nil {
		err = err1
		return
	}
	mailer.ownAddr = ownAuth.HkpAddr

	return
}

func SendEmail(eMail_ID string, subject string, message string) (err error) {
	mailer, err1 := GetMailerConf()

	if err1 != nil {
		err = err1
		return
	}

	host := mailer.host
	port := mailer.port
	userName := mailer.userName
	password := mailer.password
	from := mailer.sender
	to := []string{eMail_ID}

	log.Println("mailer.go:Sending mail to", eMail_ID)

	parameters := &struct {
		From    string
		To      string
		Subject string
		Message string
	}{
		from,
		strings.Join([]string(to), ","),
		subject,
		message,
	}

	buffer := new(bytes.Buffer)

	template := template.Must(template.New("emailTemplate").Parse(_EmailScript()))
	template.Execute(buffer, parameters)

	auth := smtp.PlainAuth("", userName, password, host)

	err = PRCSendMail(
		host+":"+port,
		auth,
		from,
		to,
		buffer.Bytes())

	return err
}

// _EmailScript returns a template for the email message to be sent
func _EmailScript() (script string) {
	return `From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"

{{.Message}}`
}

/*
 * send email by bypassing certification verification
 *
 */

// PRCSendMail connects to the server at addr, switches to TLS if
// possible, authenticates with the optional mechanism a if possible,
// and then sends an email from address from, to addresses to, with
// message msg.
func PRCSendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) (err error) {
	c, err1 := smtp.Dial(addr)

	if err1 != nil {
		err = err1
		return
	}
	if err = c.Hello("localhost"); err != nil {
		return
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		host, _, _ := net.SplitHostPort(addr)
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		//fmt.Println("starttls with config ->", config)
		if err = c.StartTLS(config); err != nil {
			return
		}

	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(a); err != nil {
				return
			}
		}
	}
	if err = c.Mail(from); err != nil {
		return
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return
		}
	}
	w, err2 := c.Data()
	if err2 != nil {
		err = err2
		return
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return
	}
	err = c.Quit()
	return

}

//IMAP
//CheckImap() checks Imap inbox for any PGP requests ,numRequests returns number of Emails found with GPG requests.
func CheckImap() (err error) {
	defer fmt.Println("IMapChecker :", err)
	defer log.Println("IMapChecker :", err)
	fmt.Println("Starting IMAP Checker")

	imapConf, err1 := GetMailerConf()

	if err1 != nil {
		err = err1
		return
	}

	imapHost := imapConf.imapHost
	port, errC := strconv.Atoi(imapConf.imapPort)
	if errC != nil {
		err = errC
		return
	}

	imapPort := uint16(port)
	userName := imapConf.userName
	password := imapConf.password
	imapFreq := imapConf.imapFreq
	procFolder := imapConf.procFolder
	pksAddr := imapConf.ownAddr

	server := &Simap.IMAPServer{imapHost, imapPort}
	imapAcct := &Simap.IMAPAccount{userName, password, server}

	ticker := time.NewTicker(time.Duration(imapFreq) * time.Second)

	for tickTime := range ticker.C {
		msgs, err := Simap.GetEMails(imapAcct, "ALL UNSEEN", "inbox", 5, true)
		var processed []uint32
		if err == nil {
			//fmt.Println("Time [uid] From -> To")
			fmt.Println("mailer.go:Checking IMAP at ", time.Now())
			for _, msg := range msgs {
				log.Println(tickTime, ": inbox [", msg.Imap_uid, "] ", msg.From, "|", msg.Subject)
				err = processEmails(pksAddr, msg)
				if err != nil { //Dont add to processed uids
					log.Println("processing id = ", msg.Imap_uid, ": ", err)
					continue
				}
				processed = append(processed, msg.Imap_uid)
			}
			//Mark Emails as Read
			err = Simap.MarkEmails(imapAcct, "inbox", "\\SEEN", processed, 20, true)
			if err != nil {
				fmt.Println("Main : Error while Marking ", err)
			}
			//Move Processed Emails to a mailbox named processed
			err = Simap.MoveEmails(imapAcct, "inbox", procFolder, processed, 20, true)
			if err != nil {
				log.Println("Eror while moving email ", processed, " : ", err)
			}

			log.Println("CheckIMAP: Processed ", len(processed), " emails out of ", len(msgs))
			fmt.Println(time.Now(), " CheckIMAP: Processed ", len(processed), " emails out of ", len(msgs))

		} else {
			log.Println(err)
			//FOrever Check for Email,hence comment out
			//ticker.Stop()
			//break
		}
	}
	return
}

func processEmails(pksAddr string, msgData Simap.MsgData) (err error) {
	/*
		PRC TODO:
		1.If Subject==ADD
			1.1Create a http.Post wth keytext=armor
		2. If Subject ==DELETE
			2.1Create a http.Post with deleteTB=body
		3.Store Response in a HTML Message
		4. Reply with email containing the HTML Reply
	*/

	if strings.ToUpper(msgData.Subject) == "ADD" {
		resp, err := http.PostForm(fmt.Sprintf("http://%s/pks/add", pksAddr), url.Values{"keytext": {msgData.Body}})
		if err != nil {
			return err
		}
		// Store response in memory. Connection may timeout if we
		// read directly from it while loading.
		var body *bytes.Buffer
		{
			defer resp.Body.Close()
			bodyBuf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			body = bytes.NewBuffer(bodyBuf)
		}
		//Send Mail with Body
		err = SendEmail(msgData.From, "PKS Add Request Processed", string(body.Bytes()))

	} else if strings.ToUpper(msgData.Subject) == "DELETE" {
		resp, err := http.PostForm(fmt.Sprintf("http://%s/prc/delete", pksAddr), url.Values{"deleteTB": {msgData.Body}})
		if err != nil {
			return err
		}
		// Store response in memory. Connection may timeout if we
		// read directly from it while loading.
		var body *bytes.Buffer
		{
			defer resp.Body.Close()
			bodyBuf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			body = bytes.NewBuffer(bodyBuf)
		}
		//Send Mail with Body
		err = SendEmail(msgData.From, "PKS Delete Request Processed", string(body.Bytes()))
	} else {
		err = errors.New("Mail is not a PKS Request.")
	}
	return
}
