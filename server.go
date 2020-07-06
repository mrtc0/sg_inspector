package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type logProvider struct {
}

func (l *logProvider) Output(i int, s string) error {
	logrus.Debug(s)
	return nil
}

type Server struct {
	slackClient *slack.Client
	redisClient *redis.Client
	cronServer  *cron.Cron
	checker     *OpenStackSecurityGroupChecker
	conf        Config
}

func NewServer(confPath string, dryRun bool) (*Server, error) {
	cfg, err := ReadConfig(confPath, dryRun)
	if err != nil {
		return nil, err
	}

	slackClient := slack.New(cfg.SlackToken)
	if os.Getenv("DEBUG") != "" {
		slack.OptionDebug(true)(slackClient)
	}

	checker := NewOpenStackChecker(cfg, slackClient)

	redisClient := redis.NewClient(
		&redis.Options{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		})

	cronServer := cron.New()
	cronServer.AddFunc(checker.Cfg.ResetInterval, func() {
		logrus.Infof("一時的に許可していたSGをリセットします")
		_, err := redisClient.Del(context.Background(), REDIS_KEY).Result()
		if err != nil {
			logrus.Errorf("%+v\n", err)
		}
	})

	return &Server{slackClient: slackClient, redisClient: redisClient, cronServer: cronServer, checker: checker, conf: cfg}, nil
}

func (s *Server) Start() error {
	logrus.Info("Start Server.")

	go s.cronServer.Run()

	http.HandleFunc("/slack/events", func(w http.ResponseWriter, r *http.Request) {
		logrus.Info("receive request")
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logrus.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
		if err != nil {
			logrus.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Printf("receive event\n")

		switch eventsAPIEvent.Type {
		case slackevents.URLVerification:
			s.urlVerificate(w, body)
		case slackevents.CallbackEvent:
			s.callbackEvent(w, eventsAPIEvent)
		}
	})

	logrus.Info("Server listening")
	return http.ListenAndServe(":8080", nil)
}

func (s *Server) urlVerificate(w http.ResponseWriter, data []byte) {
	var res *slackevents.ChallengeResponse
	if err := json.Unmarshal(data, &res); err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(res.Challenge)); err != nil {
		logrus.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) callbackEvent(w http.ResponseWriter, eventsAPIEvent slackevents.EventsAPIEvent) {
	innerEvent := eventsAPIEvent.InnerEvent
	switch event := innerEvent.Data.(type) {
	case *slackevents.ReactionAddedEvent:
		if event.Reaction == "white_check_mark" {
			logrus.Infof("%+v\n", event)
			ts, err := strconv.ParseFloat(event.Item.Timestamp, 64)
			if err != nil {
				return
			}
			param := slack.HistoryParameters{
				Latest:    "",
				Oldest:    fmt.Sprintf("%d", int(ts)),
				Count:     10,
				Inclusive: false,
				Unreads:   true,
			}
			history, err := s.slackClient.GetChannelHistory(event.Item.Channel, param)
			if err != nil {
				return
			}
			for _, msg := range history.Messages {
				if msg.Timestamp == event.Item.Timestamp {
					for _, f := range msg.Attachments[0].Fields {
						if f.Title == "ID" {
							logrus.Infof("%+v\n", f.Value)
							_, err := s.redisClient.RPush(context.Background(), REDIS_KEY, f.Value).Result()
							if err != nil {
								return
							}
							allowed_sg, err := s.redisClient.LRange(context.Background(), REDIS_KEY, 0, -1).Result()
							if err != nil {
								return
							}
							logrus.Infof("Temporary allowed security groups: %+v\n", allowed_sg)
							params := slack.PostMessageParameters{
								Username:        s.conf.Username,
								IconEmoji:       s.conf.IconEmoji,
								ThreadTimestamp: event.Item.Timestamp,
							}
							_, _, err = s.slackClient.PostMessage(s.conf.SlackChannel, slack.MsgOptionText("明日の10時までは許可しますね〜", false), slack.MsgOptionPostMessageParameters(params))
							if err != nil {
								return
							}
						}
					}
				}
			}
		}
	case *slackevents.AppMentionEvent:
		message := strings.Split(event.Text, " ")
		if len(message) < 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		command := message[1]
		switch command {
		case "ping":
			if _, _, err := s.slackClient.PostMessage(event.Channel, slack.MsgOptionText("pong", false)); err != nil {
				logrus.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
}
