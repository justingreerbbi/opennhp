export GO111MODULE := on
PluginName = auth-bridge
ServerDir = ../../../release/nhp-server

all: build
build:
	go build -buildmode=plugin -trimpath -ldflags "-s -w" -o ${ServerDir}/plugins/${PluginName}/${PluginName}.so .
	mkdir -p ${ServerDir}/plugins/${PluginName}/etc
	cp ./etc/*.toml ${ServerDir}/plugins/${PluginName}/etc/
.PHONY: all build
