package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type Account struct {
	username string
	password string
}

func password_decrypt(username, password string) string {
	// parse password as hex
	var password_bytes, username_bytes []byte
	for i := 0; i < len(password); i += 2 {
		var tmp string = password[i : i+2]
		var tmp_int int
		fmt.Sscanf(tmp, "%x", &tmp_int)
		password_bytes = append(password_bytes, byte(tmp_int))
	}
	username_bytes = []byte(username)

	// decrypt
	username_bytes = bytes.Repeat(username_bytes, len(password_bytes)/len(username_bytes)+1)
	var result []byte
	for i := 0; i < len(password_bytes); i++ {
		result = append(result, password_bytes[i]-username_bytes[i])
	}
	return string(result)
}

func remove_char_around(s string) string {
	return strings.Trim(s, "\"")
}

func parse_config_line(line string) (string, string) {
	splitn := strings.SplitN(line, "=", 2)
	if len(splitn) != 2 {
		return "", ""
	}
	key := remove_char_around(splitn[0])
	value := remove_char_around(splitn[1])
	return key, value
}

func exitOnError(err string) {
	fmt.Println(err)
	os.Exit(1)
}

func goroutine_decrypt(username, password string, c chan Account) {
	c <- Account{username, password_decrypt(username, password)}
}

func main() {
	if len(os.Args) == 1 {
		exitOnError("Usage: imail-reg-password-recover <config file> [config file] ...")
	}

	const utf_16_detect = "M\x00a\x00i\x00l\x00A\x00d\x00d\x00r"
	channel := make(chan Account, 10)
	// someone say we should close it only in sender, but not receiver.
	// but i don't understand how to achieve this...
	defer close(channel)

	for index, filename := range os.Args {
		if index == 0 {
			continue
		}

		// open file
		file, err := os.Open(filename)
		if err != nil {
			exitOnError("Error opening file: " + filename)
		}
		// make new channel for account

		var username, password string
		// list of account
		accounts := make(map[string]string)
		user_count := 0
		var email_domain_name string

		// read file line by line
		r := bufio.NewReader(file)

		for {
			line, err := r.ReadString('\n')
			line = strings.TrimSpace(line)
			if err != nil && err != io.EOF {
				fmt.Println(err)
				exitOnError("Error reading file: " + filename)
			}
			if err == io.EOF {
				break
			}

			key, value := parse_config_line(line)

			if key == "MailAddr" {
				username = strings.Split(value, "@")[0]
				email_domain_name = strings.Split(value, "@")[1]
			}
			if key == "Password" {
				if username == "" {
					panic("username is empty when reading password.")
				}
				password = value
				user_count += 1
				go goroutine_decrypt(username, password, channel)
				username, password = "", ""
			}
			if strings.Contains(line, utf_16_detect) {
				exitOnError("UTF-16 encoding detected in file \"" + filename + "\", please convert to UTF-8 first.")
			}
		}
		file.Close()
		// wait goroutine
		for i := 0; i < user_count; i++ {
			account := <-channel
			accounts[account.username] = account.password
		}

		// fmt.Print(accounts)

		json_result, _ := json.MarshalIndent(accounts, "", "    ")
		result_filename := filename + ".dec.json"
		os.WriteFile(result_filename, json_result, 0644)
		fmt.Println("Email domain name: " + email_domain_name)
		fmt.Println("Dumped " + fmt.Sprint(len(accounts)) + " entries to file: " + result_filename)
	}
}
