package policy

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/matryer/try"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PolicyArgs struct {
	Client        *kubernetes.Clientset
	Policy        string
	Namespace     string
	ConfigMapName string
}

func (policyArgs *PolicyArgs) GetClient() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	policyArgs.Client = client

	return nil
}

func (pa PolicyArgs) UpdatePolicy() error {
	err := try.Do(func(attempt int) (bool, error) {
		configMaps := pa.Client.CoreV1().ConfigMaps(pa.Namespace)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		currentPolicy, err := configMaps.Get(ctx, pa.ConfigMapName, metav1.GetOptions{})

		if currentPolicy != nil {
			currentPolicy.Data["appsettings.json"] = pa.Policy

			_, err = configMaps.Update(ctx, currentPolicy, metav1.UpdateOptions{})
		}

		if err != nil && attempt < 5 {
			time.Sleep((time.Duration(attempt) * 5) * time.Second) // exponential 5 second wait
		}

		return attempt < 5, err // try 5 times
	})

	return err
}
