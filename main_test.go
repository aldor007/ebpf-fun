package main

import "testing"
import 	"github.com/stretchr/testify/assert"

func TestEvent(t *testing.T) {
	// 75.2.92.173:80 -> 192.168.65.3:59860
	data := []byte{0, 80, 233, 212, 75, 2, 92, 173, 192, 168, 65, 3}
	event := Event{}
	event.UnmarshalBinary(data)

	assert.Equal(t, event.DPort, uint16(59860)) 
	assert.Equal(t, event.SPort, uint16(80))
	assert.Equal(t, intToIP(event.SAddr).String(), "75.2.92.173")
	assert.Equal(t, intToIP(event.DAddr).String(), "192.168.65.3")
}
func TestEventInvalid(t *testing.T) {
	data := []byte{0, 233, 212, 75, 2, 92, 173, 192, 168, 65, 3}
	event := Event{}
	err := event.UnmarshalBinary(data)

	assert.NotNil(t, err)

}