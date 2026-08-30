//go:build !linux

package main

func runningAsRoot() bool { return false }
