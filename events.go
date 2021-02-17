/*
 * MIT License (MIT)
 * Copyright (c) 2018
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package sdk

import (
	"log"
	"net/url"

	"github.com/peterhellberg/sseclient"
)

func Subscribe(host string) (chan sseclient.Event, error) {
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/activity/subscribe")
	if err != nil {
		log.Fatal(err)
	}
	events, err := sseclient.OpenURL(rel.String())

	return events, err
}
func SubscribeStream(host string, stream string) (chan sseclient.Event, error) {
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/activity/subscribe/" + stream)
	if err != nil {
		log.Fatal(err)
	}
	events, err := sseclient.OpenURL(rel.String())
	return events, err
}
func EventSubscribeContract(host string, contract string, event string) (chan sseclient.Event, error) {
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/events/" + contract + "/" + event)
	if err != nil {
		log.Fatal(err)
	}
	events, err := sseclient.OpenURL(rel.String())
	return events, err
}
func EventSubscribe(host string, contract string) (chan sseclient.Event, error) {
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/events/" + contract)
	if err != nil {
		log.Fatal(err)
	}
	events, err := sseclient.OpenURL(rel.String())
	return events, err
}
func AllEventSubscribe(host string) (chan sseclient.Event, error) {
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/events/")
	if err != nil {
		log.Fatal(err)
	}
	events, err := sseclient.OpenURL(rel.String())
	return events, err
}
