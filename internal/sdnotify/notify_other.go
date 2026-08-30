//go:build !linux

package sdnotify

func newNotifier(_ environmentLookup, _ int) (*Notifier, error) {
	return &Notifier{}, nil
}

func sendNotification(string, string) error {
	return nil
}
