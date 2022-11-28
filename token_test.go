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
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestToken(t *testing.T) {
	Convey("GenerateToken() and TokenMatches() work", t, func() {
		token, err := GenerateToken()
		So(err, ShouldBeNil)
		So(len(token), ShouldEqual, tokenLength)

		token2, err := GenerateToken()
		So(err, ShouldBeNil)
		So(len(token2), ShouldEqual, tokenLength)
		So(token, ShouldNotResemble, token2)
		So(TokenMatches(token, token2), ShouldBeFalse)
		So(TokenMatches(token, token), ShouldBeTrue)
	})

	Convey("GenerateAndStoreTokenForSelfClient() and GetStoredToken() work", t, func() {
		tdir := t.TempDir()
		tokenPath := filepath.Join(tdir, "gas.test.token")

		token, err := GenerateAndStoreTokenForSelfClient(tokenPath)
		So(err, ShouldBeNil)
		So(len(token), ShouldEqual, tokenLength)

		_, err = os.Stat(tokenPath)
		So(err, ShouldBeNil)

		token2, err := GenerateAndStoreTokenForSelfClient(tokenPath)
		So(err, ShouldBeNil)
		So(token2, ShouldResemble, token)

		token3, err := GetStoredToken(tokenPath)
		So(err, ShouldBeNil)
		So(token3, ShouldResemble, token)

		So(TokenMatches(token, token3), ShouldBeTrue)
	})
}
