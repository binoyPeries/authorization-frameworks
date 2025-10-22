package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/openfga/language/pkg/go/transformer"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	return string(b)
}

func loadModelFromDSL(dslPath string) *client.ClientWriteAuthorizationModelRequest {
	// Read the DSL file
	dslContent := readFile(dslPath)

	// Transform DSL to JSON
	jsonModel, err := transformer.TransformDSLToJSON(dslContent)
	must(err)

	// Parse JSON into ClientWriteAuthorizationModelRequest
	var authModel client.ClientWriteAuthorizationModelRequest
	must(json.Unmarshal([]byte(jsonModel), &authModel))

	return &authModel
}

func getOrCreateStore(ctx context.Context, fgaClient *client.OpenFgaClient, storeName string) (string, string, bool, error) {
	const storeIDFile = ".openfga_store_id"
	const modelIDFile = ".openfga_model_id"

	// Try to read existing store ID
	if data, err := os.ReadFile(storeIDFile); err == nil {
		storeID := string(data)
		fmt.Println("Reusing existing store:", storeID)
		fgaClient.SetStoreId(storeID)

		// Try to read existing model ID
		var modelID string
		if modelData, err := os.ReadFile(modelIDFile); err == nil {
			modelID = string(modelData)
			fmt.Println("Reusing existing model:", modelID)
			fgaClient.SetAuthorizationModelId(modelID)
		}
		return storeID, modelID, false, nil // false = not newly created
	}

	// Create new store if not exists
	fmt.Println("Creating new store...")
	store, err := fgaClient.CreateStore(ctx).Body(client.ClientCreateStoreRequest{
		Name: storeName,
	}).Execute()
	if err != nil {
		return "", "", false, err
	}

	storeID := store.GetId()
	fmt.Println("Created store:", storeID)

	// Save store ID to file
	must(os.WriteFile(storeIDFile, []byte(storeID), 0644))
	fgaClient.SetStoreId(storeID)

	// Upload the model
	model := loadModelFromDSL("model.fga")
	authModelResp, err := fgaClient.WriteAuthorizationModel(ctx).Body(*model).Execute()
	if err != nil {
		return "", "", false, err
	}

	modelID := authModelResp.GetAuthorizationModelId()
	fmt.Println("Created model:", modelID)

	// Save model ID to file
	must(os.WriteFile(modelIDFile, []byte(modelID), 0644))
	fgaClient.SetAuthorizationModelId(modelID)

	return storeID, modelID, true, nil // true = newly created
}

func main() {
	ctx := context.Background()

	// 1) Connect to OpenFGA
	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:               "http://localhost:8080",
		StoreId:              "",
		AuthorizationModelId: "",
		Credentials: &credentials.Credentials{
			Method: credentials.CredentialsMethodNone,
		},
	})
	must(err)

	// 2) Get or create store
	_, _, isNewStore, err := getOrCreateStore(ctx, fgaClient, "openchoreo-demo")
	must(err)

	// 3) Seed tuples only if this is a new store
	if isNewStore {
		fmt.Println("Seeding tuples for new store...")
		seedRaw := readFile("tuples.json")
		var seedData map[string]interface{}
		must(json.Unmarshal([]byte(seedRaw), &seedData))

		// Extract tuple_keys from the JSON structure
		writesData := seedData["writes"].(map[string]interface{})
		tupleKeysData := writesData["tuple_keys"].([]interface{})

		var tuples []client.ClientTupleKey
		for _, tk := range tupleKeysData {
			tkMap := tk.(map[string]interface{})
			tuples = append(tuples, client.ClientTupleKey{
				User:     tkMap["user"].(string),
				Relation: tkMap["relation"].(string),
				Object:   tkMap["object"].(string),
			})
		}

		_, err = fgaClient.Write(ctx).Body(client.ClientWriteRequest{
			Writes: tuples,
		}).Execute()
		must(err)
		fmt.Println("Tuples seeded successfully.")
	} else {
		fmt.Println("Skipping tuple seeding (using existing store with data).")
	}

	// Helpers
	checkFn := func(user, relation, object string) {
		resp, err := fgaClient.Check(ctx).Body(client.ClientCheckRequest{
			User:     user,
			Relation: relation,
			Object:   object,
		}).Execute()
		must(err)
		fmt.Printf("CHECK  user=%s  relation=%s  object=%s  -> %v\n", user, relation, object, resp.GetAllowed())
	}

	listObjects := func(user, relation, typ string) {
		resp, err := fgaClient.ListObjects(ctx).Body(client.ClientListObjectsRequest{
			User:     user,
			Relation: relation,
			Type:     typ,
		}).Execute()
		must(err)
		fmt.Printf("LIST_OBJECTS user=%s relation=%s type=%s -> %v\n", user, relation, typ, resp.GetObjects())
	}

	fmt.Println("\n--- ListObjects ---")

	// use case: users in team A can only work with components in project1
	// users in group teamA can view components in project1
	listObjects("group:teamA#member", "can_update", "component")
	checkFn("user:alice", "can_update", "component:project1-component1")

	//use case: user x in team devops wants to promote component2 in project1 to dev->stage
	// 1. user should be in group that has promoter role on project1
	// 2. user should be in group that have access to promote to env:stage
	checkFn("user:dan", "can_promote", "component:project1-component2")
	checkFn("user:dan", "can_deploy_to", "env:stage")

	fmt.Println("\nDone.")
}
