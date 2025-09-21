/*
Copyright 2025.

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"d7y.io/dragonfly-injector/internal/webhook/v1/injector"
	"d7y.io/dragonfly-injector/test/utils"
)

// namespace where the project is deployed in
const namespace = "dragonfly-injector-system"

// serviceAccountName created for the project
const serviceAccountName = "dragonfly-injector-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "dragonfly-injector-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "dragonfly-injector-metrics-binding"

// webhook config-map name
const webhookConfigMapName = "dragonfly-injector-inject-config"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		// By("installing CRDs")
		// cmd = exec.Command("make", "install")
		// _, err = utils.Run(cmd)
		// Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		// By("uninstalling CRDs")
		// cmd = exec.Command("make", "uninstall")
		// _, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=dragonfly-injector-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"imagePullPolicy": "IfNotPresent",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_webhook_requests_total",
			))
		})

		It("should provisioned cert-manager", func() {
			By("validating that cert-manager has the certificate Secret")
			verifyCertManager := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secrets", "webhook-server-cert", "-n", namespace)
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyCertManager).Should(Succeed())
		})

		It("should have CA injection for mutating webhooks", func() {
			By("checking CA injection for mutating webhooks")
			verifyCAInjection := func(g Gomega) {
				cmd := exec.Command("kubectl", "get",
					"mutatingwebhookconfigurations.admissionregistration.k8s.io",
					"dragonfly-injector-mutating-webhook-configuration",
					"-o", "go-template={{ range .webhooks }}{{ .clientConfig.caBundle }}{{ end }}")
				mwhOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(len(mwhOutput)).To(BeNumerically(">", 10))
			}
			Eventually(verifyCAInjection).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput := getMetricsOutput()
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	})

	Context("BasicInjectionTests", func() {
		It("should inject when namespace has dragonfly.io/inject=true label", func() {
			By("creating a test namespace with injection label")
			testNamespace := "test-namespace-injection"
			cmd := exec.Command("kubectl", "create", "ns", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

			By("labeling the namespace to enable injection")
			injectLable := injector.NamespaceInjectLabelName + "=" + injector.NamespaceInjectLabelValue
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", testNamespace,
				injectLable,
				"pod-security.kubernetes.io/enforce=restricted")
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to label namespace")

			By("creating a simple pod in the labeled namespace")
			pod := &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: testNamespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "busybox:latest",
							Command: []string{
								"sleep",
								"infinity",
							},
						},
					},
				},
			}
			podYamlBytes, err := yaml.Marshal(pod)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal pod to yaml")
			tempDir := GinkgoT().TempDir()
			podFile := filepath.Join(tempDir, "test-pod.yaml")
			err = os.WriteFile(podFile, podYamlBytes, 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write pod yaml to file")

			cmd = exec.Command("kubectl", "apply", "-f", podFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test pod")

			By("waiting for the pod to be running")
			Eventually(verifyPodIsRunning(testNamespace, "test-pod")).Should(Succeed())

			By("verifying P2P configurations are injected")
			Eventually(verifyInjection(testNamespace, "test-pod")).Should(Succeed())

			By("cleaning up test resources")
			cmd = exec.Command("kubectl", "delete", "pod", "test-pod", "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test pod")

			cmd = exec.Command("kubectl", "delete", "ns", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test namespace")
		})

		It("should inject when pod has dragonfly.io/inject=true annotation", func() {
			By("creating a test pod with injection annotation")
			testNamespace := "test-namespace-injection"
			cmd := exec.Command("kubectl", "create", "ns", testNamespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

			pod := &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: testNamespace,
					Annotations: map[string]string{
						injector.PodInjectAnnotationName: injector.PodInjectAnnotationValue,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "busybox:latest",
							Command: []string{
								"sleep",
								"infinity",
							},
						},
					},
				},
			}
			podYamlBytes, err := yaml.Marshal(pod)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal pod to yaml")
			tempDir := GinkgoT().TempDir()
			podFile := filepath.Join(tempDir, "test-pod.yaml")
			err = os.WriteFile(podFile, podYamlBytes, 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write pod yaml to file")

			cmd = exec.Command("kubectl", "apply", "-f", podFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test pod")

			By("waiting for the pod to be running")
			Eventually(verifyPodIsRunning(testNamespace, "test-pod")).Should(Succeed())

			By("verifying P2P configurations are injected")
			Eventually(verifyInjection(testNamespace, "test-pod")).Should(Succeed())

			By("cleaning up test resources")
			cmd = exec.Command("kubectl", "delete", "pod", "test-pod", "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test pod")

			cmd = exec.Command("kubectl", "delete", "ns", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test namespace")

		})

		It("should not inject when configmap is disbale", func() {
			By("get original configmap")
			cmd := exec.Command("kubectl", "get", "cm", webhookConfigMapName, "-n", namespace, "-o", `jsonpath={.data."config\.yaml"}`)
			configYaml, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to get configmap")
			config := injector.InjectConf{}
			err = yaml.Unmarshal([]byte(configYaml), &config)
			Expect(err).NotTo(HaveOccurred(), "Failed to unmarshal configmap")

			By("disable webhook injection")
			config.Enable = false
			configBytes, err := yaml.Marshal(&config)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal configmap")
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      webhookConfigMapName,
					Namespace: namespace,
				},
				Data: map[string]string{
					"config.yaml": string(configBytes),
				},
			}

			By("update configmap")
			cmYaml, err := yaml.Marshal(cm)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal configmap")
			cmFile := filepath.Join(GinkgoT().TempDir(), "configmap.yaml")
			err = os.WriteFile(cmFile, cmYaml, 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write configmap yaml to file")
			cmd = exec.Command("kubectl", "apply", "-f", cmFile, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to update configmap")

			By("wait for configmap update")
			time.Sleep(injector.ConfigReloadWaitTime)

			By("creating a test pod with injection annotation")
			testNamespace := "test-namespace-injection"
			cmd = exec.Command("kubectl", "create", "ns", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")

			pod := &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: testNamespace,
					Annotations: map[string]string{
						injector.PodInjectAnnotationName: injector.PodInjectAnnotationValue,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "busybox:latest",
							Command: []string{
								"sleep",
								"infinity",
							},
						},
					},
				},
			}
			podYamlBytes, err := yaml.Marshal(pod)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal pod to yaml")
			tempDir := GinkgoT().TempDir()
			podFile := filepath.Join(tempDir, "test-pod.yaml")
			err = os.WriteFile(podFile, podYamlBytes, 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write pod yaml to file")

			cmd = exec.Command("kubectl", "apply", "-f", podFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test pod")

			By("waiting for the pod to be running")
			Eventually(verifyPodIsRunning(testNamespace, "test-pod")).Should(Succeed())

			By("verifying P2P configurations are not injected")
			Eventually(verifyInjection(namespace, "test-pod")).ShouldNot(Succeed())

			By("resetting configmap")
			cm.Data["config.yaml"] = configYaml
			cmYaml, err = yaml.Marshal(cm)
			Expect(err).NotTo(HaveOccurred(), "Failed to marshal configmap")
			err = os.WriteFile(cmFile, cmYaml, 0644)
			Expect(err).NotTo(HaveOccurred(), "Failed to write configmap yaml to file")
			cmd = exec.Command("kubectl", "apply", "-f", cmFile, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to update configmap")

			By("wait for configmap update")
			time.Sleep(injector.ConfigReloadWaitTime)

			By("cleaning up test resources")
			cmd = exec.Command("kubectl", "delete", "pod", "test-pod", "-n", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test pod")

			cmd = exec.Command("kubectl", "delete", "ns", testNamespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete test namespace")
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

func verifyPodIsRunning(podName, namespace string) func(g Gomega) {
	return func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pod", podName,
			"-n", namespace, "-o", "jsonpath={.status.phase}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Running"), "Pod should be running")
	}
}

func verifyInjection(podName, namespace string) func(g Gomega) {
	return func(g Gomega) {
		// Check for environment variables
		cmd := exec.Command("kubectl", "exec", podName, "-n", namespace,
			"--", "env")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(ContainSubstring(injector.ProxyEnvName),
			"Should have dragonfly proxy env var")
		g.Expect(output).To(ContainSubstring(injector.CliToolsPathEnvName),
			"Should have dragonfly tools path env var")

		// Check for volume mounts and init container
		cmd = exec.Command("kubectl", "get", "pod", podName, "-n", namespace,
			"-o", "json")
		podJson, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(podJson).To(ContainSubstring(injector.DfdaemonUnixSockVolumeName),
			"Should have dfdaemon socket volume")
		g.Expect(podJson).To(ContainSubstring(injector.CliToolsVolumeName),
			"Should have cli tools volume")
		g.Expect(podJson).To(ContainSubstring(injector.CliToolsInitContainerName),
			"Should have cli tools init container")
	}
}
