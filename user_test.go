/*******************************************************************************
 * Copyright (c) 2022 Genome Research Ltd.
 *
 * Author: Sendu Bala <sb10@sanger.ac.uk>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

package server

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUser(t *testing.T) {
	username, uid := GetUser(t)

	Convey("Given a User", t, func() {
		u := &User{Username: username, UID: uid}

		Convey("You can get its GIDs", func() {
			gids, err := u.GIDs()
			So(err, ShouldBeNil)
			So(len(gids), ShouldBeGreaterThanOrEqualTo, 1)

			Convey("Unless UID is not set", func() {
				u.UID = ""
				gids, err = u.GIDs()
				So(err, ShouldBeNil)
				So(gids, ShouldBeNil)
			})

			Convey("Unless UID is invalid", func() {
				u.UID = "-1"
				_, err = u.GIDs()
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("UserNameToUID works, returning an error with invalid users", t, func() {
		uid, err := UserNameToUID(username)
		So(err, ShouldBeNil)
		So(uid, ShouldEqual, uid)

		_, err = UserNameToUID("!@£@$")
		So(err, ShouldNotBeNil)
	})
}
