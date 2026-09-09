// Copyright (c) 2026 Codestra
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/codestra/plugins/codestra-jwt-replay"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: replayauth.Factory,
		TLSProviderFunc: api.VaultPluginTLSProvider(apiClientMeta.GetTLSConfig()),
	}); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
