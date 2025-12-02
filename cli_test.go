package server

import (
	"os/user"
	"testing"

	. "github.com/smartystreets/goconvey/convey" //nolint:revive
)

func TestNewClientCLI(t *testing.T) {
	Convey("NewClientCLI username handling", t, func() {
		Convey("uses the provided username when given", func() {
			c, err := NewClientCLI("jwt", "servertoken", "example.com", "", false, "alice")
			So(err, ShouldBeNil)
			So(c.user, ShouldEqual, "alice")
		})

		Convey("falls back to current user when not provided", func() {
			u, err := user.Current()
			So(err, ShouldBeNil)

			c, err := NewClientCLI("jwt", "servertoken", "example.com", "", false)
			So(err, ShouldBeNil)
			So(c.user, ShouldEqual, u.Username)
		})
	})
}
