package utils

import "time"

type IncrementalSleeper struct {
	SleepTime        time.Duration
	MaxSleepTime     time.Duration
	InitialSleepTime time.Duration
}

func (is *IncrementalSleeper) increase() {
	newSleepTime := is.SleepTime * 2
	if newSleepTime > is.MaxSleepTime {
		newSleepTime = is.MaxSleepTime
	}
	is.SleepTime = newSleepTime
}

func (is *IncrementalSleeper) Reset() {
	is.SleepTime = is.InitialSleepTime
}

func (is *IncrementalSleeper) Sleep() {
	time.Sleep(is.SleepTime)
	is.increase()
}
