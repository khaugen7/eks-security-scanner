package kube

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func GetClient() *kubernetes.Clientset {
	homedir, _ := os.UserHomeDir()
	kubeconfig := filepath.Join(homedir, ".kube", "config")
	log.Debugf("Obtaining kube config from %s\n", kubeconfig)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return clientset
}
