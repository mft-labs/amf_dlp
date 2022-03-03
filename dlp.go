/****************************************************************************
 *
 * Copyright (C) Agile Data, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by MFTLABS <code@mftlabs.io>
 *
 ****************************************************************************/
package dlp

import (
	"bufio"
	"encoding/json"

	//"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	//"time"

	"github.com/alecthomas/log4go"
)

type IcapClient struct {
	tlsflag     bool
	serverIP    string
	port        string
	icapService string
	previewSize int64
	filename    string
	writer      *bufio.Writer
	reader      *bufio.Reader
	log         log4go.Logger
}

const (
	BUFFER_LENGTH    = 8192
	VERSION          = "1.0"
	USERAGENT        = "AMF ICAP Client"
	DELIM            = "\r\n"
	PREVIEW_EOF_TERM = "0; ieof\r\n\r\n"
	PREVIEW_TERM     = "0\r\n\r\n"
)

func (ic *IcapClient) Init(avurl string, log log4go.Logger) error {
	url, err := url.Parse(avurl)
	if err != nil {
		return fmt.Errorf("Error parsing ICAP server URL - %v", err)
	}
	ic.icapService = strings.Replace(url.Path, "/", "", -1)
	ic.serverIP = url.Hostname()
	ic.port = url.Port()
	ic.tlsflag = url.Scheme == "icaps"
	ic.log = log
	return nil
}

func (ic *IcapClient) getIpAddress() string {
	ifaces, err := net.Interfaces()
	if err == nil {
	var ip net.IP
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		// handle err
		if err == nil {
			for _, addr := range addrs {
				switch v := addr.(type) {
					case *net.IPNet:
							ip = v.IP
					case *net.IPAddr:
							ip = v.IP
				}

			}
		}
	}
	return ip.To4().String()
	}
	return ""
	
}

func (ic *IcapClient) Scan(filename string) (errorReason error) {
	// current version connects each time, we can improve this
	err := ic.connect()
	if err != nil {
		return err
	}
	err = ic.optionRequest()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error reading options from ICAP server - %v", err))
		return fmt.Errorf("Error reading options from ICAP server - %v", err)
	}
	options, err := ic.getHeaders()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error reading headers from ICAP server - %v", err))
		return fmt.Errorf("Error reading headers from ICAP server - %v", err)
	}
	status := options["Status"]
	if status == "204" || status == "200" {
		ic.previewSize, _ = strconv.ParseInt(options["Preview"], 10, 64)
		if ic.previewSize == 0 {
			ic.log.Debug(fmt.Sprintf("Error, ICAP server did not return a preview size"))
			//return fmt.Errorf("Error, ICAP server did not return a preview size")
			ic.previewSize = 30
		}
	} else {
		ic.log.Debug(fmt.Sprintf("Error response from ICAP server - " + status))
		return fmt.Errorf("Error response from ICAP server - " + status)
	}
	ic.log.Debug(fmt.Sprintf("Preview Size is %v",ic.previewSize))
	stat, err := os.Stat(filename)
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error getting input file length - %v", err))
		return fmt.Errorf("Error getting input file length - %v", err)
	}
	return ic.scanFile(filename, stat.Size())
}

func (ic *IcapClient) connect() error {
	config := tls.Config{
		//		Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	if ic.tlsflag {
		conn, err := tls.Dial("tcp", ic.serverIP+":"+ic.port, &config)
		if err != nil {
			conn.Close()
			ic.log.Debug(fmt.Sprintf("Error connecting to ICAP server - %v", err))
			return fmt.Errorf("Error connecting to ICAP server - %v", err)
		}
		//ic.Conn2 = conn.(*tls.Conn)
		//ic.ConnMode = 1
		ic.writer = bufio.NewWriter(conn)
		ic.reader = bufio.NewReader(conn)
	} else {
		conn, err := net.Dial("tcp", ic.serverIP+":"+ic.port)
		
		if err != nil {
			//			defer conn.Close()
			ic.log.Debug(fmt.Sprintf("Error connecting to ICAP server - %v", err))
			return fmt.Errorf("Error connecting to ICAP server - %v", err)
		}
		//conn.(*net.TCPConn).SetKeepAlive(true)
		//conn.(*net.TCPConn).SetKeepAlivePeriod(120 * time.Second)
		//ic.ConnMode=2
		//ic.Conn = conn.(*net.TCPConn)
		ic.writer = bufio.NewWriter(conn)
		ic.reader = bufio.NewReader(conn)
	}
	return nil
}

func (ic *IcapClient) optionRequest() error {
	s := []string{
		"OPTIONS icap://" + ic.serverIP + "/" + ic.icapService + " ICAP/" + VERSION + DELIM,
		"Host: " + ic.serverIP + DELIM,
		"User-Agent: " + USERAGENT + DELIM,
		"Encapsulated: null-body=0" + DELIM + DELIM,
	}
	ic.log.Debug("Sending Headers to ICAP Server")
	ic.log.Debug(fmt.Sprintf("%v",strings.Join(s, "")))
	request := strings.Join(s, "")
	_, err := ic.writer.WriteString(request)
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error writing request to ICAP server - %v", err))
		return fmt.Errorf("Error writing request to ICAP server - %v", err)
	}
	err = ic.writer.Flush()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error writing request to ICAP server - %v", err))
		return fmt.Errorf("Error writing request to ICAP server - %v", err)
	}
	return nil
}

func (ic *IcapClient) getHeaders() (map[string]string, error) {
	headers := make(map[string]string)

	for {
		//line, _, err := ic.reader.ReadLine()
		line,err := ic.reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		val := string(line)
		ic.log.Debug(val)
		val = strings.TrimSpace(val)
		if val == "" {
			break
		}
		
		if strings.HasPrefix(val, "ICAP") || strings.HasPrefix(val, "HTTP") {
			vals := strings.Fields(val)
			if len(vals) > 2 {
				headers["Version"] = vals[0]
				headers["Status"] = vals[1]
				//				fmt.Printf("status: [%s]\n", vals[1])
				headers["Reason"] = vals[2]
			}
			continue
		}
		vals := strings.SplitN(val, ":", 2)
		if len(vals) > 1 {
			//			fmt.Printf("key: %s=%s\n", vals[0], vals[1])
			key := strings.TrimSpace(vals[0])
			value := strings.TrimSpace(vals[1])
			headers[key] = value
		}
	}
	return headers, nil
}

func (ic *IcapClient) scanFile(filename string, fsize int64) error {

	input, err := os.Open(filename)
	ic.log.Debug(fmt.Sprintf("File Size:%v",fsize))
	if err != nil {
		return fmt.Errorf("Error opening input file - %v", err)
	}
	fbase := path.Base(filename)
	//resHeader := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", fbase, ic.serverIP, ic.port)
	resHeader := fmt.Sprintf("POST /%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", fbase, ic.serverIP, ic.port)
	resBody := fmt.Sprintf("%sHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: %d\r\n\r\n", resHeader, fsize)
	ic.log.Debug(resHeader)
	ic.log.Debug(resBody)
	previewSize := ic.previewSize
	if fsize < ic.previewSize {
		previewSize = fsize
	}

	hexSize := fmt.Sprintf("%X", previewSize)
	headerLen := strconv.Itoa(len(resHeader))
	bodyLen := strconv.Itoa(len(resBody))
	preLen := strconv.FormatInt(previewSize, 10)

	s := []string{
		//"REQMOD icap://" + ic.serverIP + "/" + ic.icapService + " ICAP/" + VERSION + DELIM,
		"RESPMOD icap://" + ic.serverIP + "/" + ic.icapService + " ICAP/" + VERSION + DELIM,
		"Host: " + ic.serverIP + DELIM,
		"X-Client-IP: "+ ic.getIpAddress() + DELIM,
		"Connection:  close" + DELIM,
		//"Connection:  Keep-Alive" + DELIM,
		"User-Agent: " + USERAGENT + DELIM,
		"Allow: 204" + DELIM,
		"Preview: " + preLen + DELIM,
		"Encapsulated: req-hdr=0, res-hdr=" + headerLen + ", res-body=" + bodyLen + DELIM + DELIM,
		resBody,
		hexSize + DELIM,
	}
	ic.log.Debug(strings.Join(s, ""))
	buffer := strings.Join(s, "")
	_, err = ic.writer.WriteString(buffer)
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error writing data to ICAP server: - %v", err))
		return fmt.Errorf("Error writing data to ICAP server: - %v", err)
	}

	buf := make([]byte, previewSize)
	_, err = io.ReadAtLeast(input, buf, int(previewSize))
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error reading input file - %v", err))
		return fmt.Errorf("Error reading input file - %v", err)
	}
	ic.writer.Write(buf)
	ic.writer.WriteString(DELIM)
	if fsize <= previewSize {
		ic.writer.WriteString(PREVIEW_EOF_TERM)
	} else {
		ic.writer.WriteString(PREVIEW_TERM)
	}
	err = ic.writer.Flush()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error writing data to ICAP server - %v", err))
		return fmt.Errorf("Error writing data to ICAP server - %v", err)
	}

	if fsize > previewSize {
		resp, err := ic.getHeaders()
		if err != nil {
			ic.log.Debug(fmt.Sprintf("Error reading headers from ICAP server - %v", err))
			return fmt.Errorf("Error reading headers from ICAP server - %v", err)

		}
		output,_:=json.Marshal(resp)
		ic.log.Debug(fmt.Sprintf("\nResponse Headers:%s",string(output)))
		status := resp["Status"]
		ic.log.Debug(fmt.Sprintf("Status received %s",status))
		defect := ""
		if _,ok:=resp["X-Block-Reason"]; ok {
			defect =  resp["X-Block-Reason"]
		}
		switch status {
		case "100":
			break // continue transfer
		case "200":
			return fmt.Errorf("File not accepted, reason: %v",defect)
			//break
		case "204":
			//break // accepted
			return nil
		case "403":
			return fmt.Errorf("File not accepted, reason: %v",defect)
		case "404":
			ic.log.Debug(fmt.Sprintf("Error, ICAP service not found"))
			return fmt.Errorf("Error, ICAP service not found")
		default:
			return fmt.Errorf("Error, unexpected status from server - %s", status)
		}
	}

	//Sending remaining part of file
	if fsize > previewSize {
		
		buf := make([]byte, BUFFER_LENGTH)
		for {
			num, err := input.Read(buf)
			hexSize := fmt.Sprintf("%X", num)
			
			if num == 0 {
				break
			}
			if err == io.EOF {
				break
			}
			ic.log.Debug(fmt.Sprintf("Sending remaining part of file: %X",num))
			ic.writer.WriteString(hexSize + DELIM)
			//ic.log.Debug(fmt.Sprintf("%s", hexSize+DELIM))
			//buf = bytes.Replace(buf,[]byte(DELIM),[]byte(""),-1)
			//buf = bytes.Replace(buf,[]byte("\n"),[]byte(""),-1)
			ic.writer.Write(buf[0:num])
			//ic.log.Debug(fmt.Sprintf("%s",string(buf[0:num])))
			ic.writer.WriteString(DELIM)
			//ic.log.Debug(fmt.Sprintf(DELIM))
		}
		ic.writer.WriteString(PREVIEW_TERM)
		ic.log.Debug(PREVIEW_TERM)
		ic.writer.Flush()
	}
	if ic.writer == nil {
		ic.log.Debug("========= Connection closed!")
	}
	ic.log.Debug("Retrieving headers from response")
	resp2, err := ic.getHeaders()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error reading headers from ICAP server - %v", err))
		return fmt.Errorf("Error reading headers from ICAP server - %v", err)
	}
	output,_:=json.Marshal(resp2)
	ic.log.Debug(fmt.Sprintf("\nResponse Headers:%s",string(output)))
	status := resp2["Status"]
	ic.log.Debug(fmt.Sprintf("Status received %s",status))
	switch status {
	case "200":
		//return fmt.Errorf("Returned 200")
		break
	case "204":
		return nil // passed
	}
	nresp, err := ic.getHeaders()
	if err != nil {
		ic.log.Debug(fmt.Sprintf("Error reading headers from ICAP server - %v", err))
		return fmt.Errorf("Error reading headers from ICAP server - %v", err)
	}
	status = nresp["Status"]
	ic.log.Debug(fmt.Sprintf("Status received %s",status))
	
	headersReceived := ""
	
	for k, v := range nresp {
		headersReceived = fmt.Sprintf("%s\nk=%s, v=%s", headersReceived, k, v)
	}
	if status == "403" {
		classificationBlock := ""
		if _,ok := nresp["X-Block-Reason"]; ok {
			classificationBlock = resp2["X-Block-Reason"]
		}
		ic.log.Debug(fmt.Sprintf("File not accepted"))
		if strings.Contains(classificationBlock,"DLP") {
			ic.log.Debug("DLP Classification Block found")
			return fmt.Errorf("File not accepted, DLP Classification Block found")
		} else {

			ic.log.Debug("Virus found with signature %s", nresp["X-Virus-ID"])

			virusName := nresp["X-Virus-ID"]
			if  virusName == "" {

				bufsize, err := strconv.Atoi(nresp["Content-Length"])
				if err != nil {
					bufsize = 8092
				}
				buf2 := make([]byte, bufsize)
				for {
					len1, err := ic.reader.Read(buf2)
					if err == io.EOF {
						break
					}
					if len1 == 0 {
						break
					}
					label := "<b>Virus Name: </b>"
					contents := string(buf2)
					if strings.Contains(contents,"Virus Name:") {
						pos1 := strings.Index(contents,label)
						pos2 := strings.Index(string(contents[pos1:]),"<br />")
						ic.log.Debug(fmt.Sprintf("The string found between %d and %d",pos1,pos2))
						virusName = string(contents[pos1+len(label):pos1+pos2])
						break
					}
				}

			}
			return fmt.Errorf("File not accepted, Virus found with signature %s", virusName)
		}

		//return fmt.Errorf("File not accepted")
	}
	if status == "307" {
		ic.log.Debug("Virus found with signature %s", nresp["X-Virus-ID"])
		return fmt.Errorf("Virus found with signature %s", nresp["X-Virus-ID"])
		//return fmt.Errorf("File not accepted")
	}
	//return nil
	ic.log.Debug(fmt.Sprintf("Error, unexpected response from ICAP server - %v - %v", status, headersReceived))
	return fmt.Errorf("Error, unexpected response from ICAP server - %v - %v", status, headersReceived)
}
