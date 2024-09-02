/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awsclient "github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	awssm "github.com/aws/aws-sdk-go/service/secretsmanager"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	prov "github.com/external-secrets/external-secrets/apis/providers/v1alpha1"
	awsauth "github.com/external-secrets/external-secrets/pkg/provider/aws/auth"
	"github.com/external-secrets/external-secrets/pkg/provider/aws/parameterstore"
	"github.com/external-secrets/external-secrets/pkg/provider/aws/secretsmanager"
	"github.com/external-secrets/external-secrets/pkg/provider/aws/util"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1beta1.Provider = &Provider{}

// Provider satisfies the provider interface.
type Provider struct {
	storeKind string
}

const (
	errUnableCreateSession    = "unable to create session: %w"
	errUnknownProviderService = "unknown AWS Provider Service: %s"
	errRegionNotFound         = "region not found: %s"
	errInitAWSProvider        = "unable to initialize aws provider: %s"
	errInvalidSecretsManager  = "invalid SecretsManager settings: %s"
)

func (p *Provider) Convert(in esv1beta1.GenericStore) (client.Object, error) {
	out := &prov.AWS{}
	tmp := map[string]interface{}{
		"spec": in.GetSpec().Provider.AWS,
	}
	d, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(d, out)
	if err != nil {
		return nil, fmt.Errorf("could not convert %v in a valid fake provider: %w", in.GetName(), err)
	}
	return out, nil
}

// Capabilities return the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (p *Provider) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadWrite
}

func (p *Provider) ApplyReferent(spec client.Object, caller esmeta.ReferentCallOrigin, _ string) (client.Object, error) {
	converted, ok := spec.(*prov.AWS)
	out := converted.DeepCopy()
	if !ok {
		return nil, fmt.Errorf("could not convert source object %v into 'fake' provider type: object from type %T", spec.GetName(), spec)
	}
	switch caller {
	case esmeta.ReferentCallClusterSecretStore:
		p.storeKind = esv1beta1.ClusterSecretStoreKind
	case esmeta.ReferentCallSecretStore:
	case esmeta.ReferentCallProvider:
	default:
	}
	return out, nil
}
func (p *Provider) NewClientFromObj(ctx context.Context, object client.Object, kube client.Client, namespace string) (esv1beta1.SecretsClient, error) {
	store, ok := object.(*prov.AWS)
	if !ok {
		return nil, errors.New("could not load aws provider")
	}
	return newClient(ctx, store, kube, namespace, p.storeKind, awsauth.DefaultSTSProvider)
}

// NewClient constructs a new secrets client based on the provided store.
func (p *Provider) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube client.Client, namespace string) (esv1beta1.SecretsClient, error) {
	return nil, errors.New("no longer supported")
}

func (p *Provider) ValidateStore(store esv1beta1.GenericStore) (admission.Warnings, error) {
	prov, err := util.GetAWSProvider(store)
	if err != nil {
		return nil, err
	}
	err = validateRegion(prov)
	if err != nil {
		return nil, err
	}
	err = validateSecretsManagerConfig(prov)
	if err != nil {
		return nil, err
	}

	// case: static credentials
	if prov.Auth.SecretRef != nil {
		if err := utils.ValidateReferentSecretSelector(store, prov.Auth.SecretRef.AccessKeyID); err != nil {
			return nil, fmt.Errorf("invalid Auth.SecretRef.AccessKeyID: %w", err)
		}
		if err := utils.ValidateReferentSecretSelector(store, prov.Auth.SecretRef.SecretAccessKey); err != nil {
			return nil, fmt.Errorf("invalid Auth.SecretRef.SecretAccessKey: %w", err)
		}
		if prov.Auth.SecretRef.SessionToken != nil {
			if err := utils.ValidateReferentSecretSelector(store, *prov.Auth.SecretRef.SessionToken); err != nil {
				return nil, fmt.Errorf("invalid Auth.SecretRef.SessionToken: %w", err)
			}
		}
	}

	// case: jwt credentials
	if prov.Auth.JWTAuth != nil && prov.Auth.JWTAuth.ServiceAccountRef != nil {
		if err := utils.ValidateReferentServiceAccountSelector(store, *prov.Auth.JWTAuth.ServiceAccountRef); err != nil {
			return nil, fmt.Errorf("invalid Auth.JWT.ServiceAccountRef: %w", err)
		}
	}

	return nil, nil
}

func validateRegion(prov *esv1beta1.AWSProvider) error {
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	found := false
	for _, p := range partitions {
		var serviceskey string
		if prov.Service == esv1beta1.AWSServiceSecretsManager {
			serviceskey = "secretsmanager"
		} else if prov.Service == esv1beta1.AWSServiceParameterStore {
			serviceskey = "ssm"
		}
		service, ok := p.Services()[serviceskey]
		if ok {
			for region := range service.Endpoints() {
				if region == prov.Region {
					found = true
				}
			}
		}
	}
	if !found {
		return fmt.Errorf(errRegionNotFound, prov.Region)
	}
	return nil
}

func validateSecretsManagerConfig(prov *esv1beta1.AWSProvider) error {
	if prov.SecretsManager == nil {
		return nil
	}
	return util.ValidateDeleteSecretInput(awssm.DeleteSecretInput{
		ForceDeleteWithoutRecovery: &prov.SecretsManager.ForceDeleteWithoutRecovery,
		RecoveryWindowInDays:       &prov.SecretsManager.RecoveryWindowInDays,
	})
}

func newClient(ctx context.Context, store *prov.AWS, kube client.Client, namespace, storeKind string, assumeRoler awsauth.STSProvider) (esv1beta1.SecretsClient, error) {
	if store == nil {
		return nil, fmt.Errorf(errInitAWSProvider, "nil store")
	}
	storeSpec := store.Spec
	var cfg *aws.Config

	// allow SecretStore controller validation to pass
	// when using referent namespace.
	if util.IsReferentSpec(storeSpec.Auth) && namespace == "" &&
		storeKind == esv1beta1.ClusterSecretStoreKind {
		cfg = aws.NewConfig().WithRegion("eu-west-1").WithEndpointResolver(awsauth.ResolveEndpoint())
		sess := &session.Session{Config: cfg}
		switch storeSpec.Service {
		case prov.AWSServiceSecretsManager:
			return secretsmanager.New(sess, cfg, storeSpec.SecretsManager, true)
		case prov.AWSServiceParameterStore:
			return parameterstore.New(sess, cfg, storeSpec.Prefix, true)
		}
		return nil, fmt.Errorf(errUnknownProviderService, storeSpec.Service)
	}

	sess, err := awsauth.New(ctx, store, kube, namespace, storeKind, assumeRoler, awsauth.DefaultJWTProvider)
	if err != nil {
		return nil, fmt.Errorf(errUnableCreateSession, err)
	}

	// Setup retry options, if present in storeSpec
	if storeSpec.RetrySettings != nil {
		var retryAmount int
		var retryDuration time.Duration

		if storeSpec.RetrySettings.MaxRetries != nil {
			retryAmount = int(*storeSpec.RetrySettings.MaxRetries)
		} else {
			retryAmount = 3
		}

		if storeSpec.RetrySettings.RetryInterval != nil {
			retryDuration, err = time.ParseDuration(*storeSpec.RetrySettings.RetryInterval)
		}
		if err != nil {
			return nil, fmt.Errorf(errInitAWSProvider, err)
		}
		awsRetryer := awsclient.DefaultRetryer{
			NumMaxRetries:    retryAmount,
			MinRetryDelay:    retryDuration,
			MaxThrottleDelay: 120 * time.Second,
		}
		cfg = request.WithRetryer(aws.NewConfig(), awsRetryer)
	}

	switch storeSpec.Service {
	case prov.AWSServiceSecretsManager:
		return secretsmanager.New(sess, cfg, storeSpec.SecretsManager, false)
	case prov.AWSServiceParameterStore:
		return parameterstore.New(sess, cfg, storeSpec.Prefix, false)
	}
	return nil, fmt.Errorf(errUnknownProviderService, storeSpec.Service)
}

func init() {
	esv1beta1.Register(&Provider{}, &esv1beta1.SecretStoreProvider{
		AWS: &esv1beta1.AWSProvider{},
	})
}
