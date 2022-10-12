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
	"embed"
	"io/fs"
	"net/http"
	"os"
)

const DevEnvKey = "GAS_DEV"
const DevEnvVal = "1"

// AddStaticPage adds the given document root to the Router() at the given
// absolute query path. Files within the document root will then be served.
//
// The files will be embedded by default, using the given embed.FS.
// You can create one of these by saying in your package:
// //go:embed static
// var staticFS embed.FS
//
// For a live view of the files in a running server, set the env var GAS_DEV to
// 1.
func (s *Server) AddStaticPage(staticFS embed.FS, rootDir, path string) {
	var fsys fs.FS

	if os.Getenv(DevEnvKey) == DevEnvVal {
		fsys = os.DirFS(rootDir)
	} else {
		fsys, _ = fs.Sub(staticFS, rootDir) //nolint:errcheck
	}

	s.router.StaticFS(path, http.FS(fsys))
}
