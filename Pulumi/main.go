package main

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/c-robinson/iplib"
	"github.com/joho/godotenv"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		/** Set pulumi context */
		SetPulumiContext(ctx)
		godotenv.Load()

		// Create VPC
		awsVpc, err := CreateVpc(os.Getenv("VPC"), os.Getenv("CIDR")+"/"+os.Getenv("MASK"), os.Getenv("VPC_TAG"), os.Getenv("VPC_TENANCY"))
		if err != nil {
			return err
		}

		// Create and attach internet gateway
		igw, err := CreateInternetGateway(os.Getenv("INTERNET_GATEWAY"), awsVpc.ID(), os.Getenv("INTERNET_GATEWAY_TAG"))
		if err != nil {
			return err
		}

		// Create public route table with internet route
		publicRouteTable, err := CreateRouteTable(awsVpc.ID(), os.Getenv("PUBLIC_ROUTE_TBL"), os.Getenv("PUBLIC_ROUTE_TBL_TAG"))
		if err != nil {
			return err
		}
		_, err = ec2.NewRoute(ctx, os.Getenv("PUBLIC_ROUTE"), &ec2.RouteArgs{
			RouteTableId:         publicRouteTable.ID(),
			DestinationCidrBlock: pulumi.String(os.Getenv("INTERNET_GATEWAY")),
			GatewayId:            igw.ID(),
		})

		// Create private route table
		privateRouteTable, err := CreateRouteTable(awsVpc.ID(), os.Getenv("PVT_ROUTE_TBL"), os.Getenv("PVT_ROUTE_TBL_TAG"))
		if err != nil {
			return err
		}

		// Get availability zones
		az, err := GetAvailabilityZones()
		if err != nil {
			return err
		}

		if len(az.Names) < 3 {
			err := os.Setenv("NO_SUBNETS", ""+strconv.Itoa(2*len(az.Names)))
			if err != nil {
				return err
			}
		}

		// Create public and private subnets
		blocks := GetCidrBlocks()
		sblen, err := strconv.Atoi(os.Getenv("NO_SUBNETS"))
		if err != nil {
			return err
		}
		//var publicSubnetIds []pulumi.IDOutput
		var publicSubnetIds pulumi.StringArray
		// var publicSubnets []*ec2.Subnet
		var privateSubnetIds pulumi.StringArray
		// var tmp_publicSubnetIds pulumi.StringArray
		for i := 0; i < sblen; i = i + 2 {
			publicSubnet, err := CreateSubnet(az.Names[i/2], "public-subnet-"+strconv.Itoa(i), awsVpc.ID(), blocks[i], true, os.Getenv("PUBLIC_SUBNET_PREFIX"))
			if err != nil {
				return err
			}

			// publicSubnets = append(publicSubnets, publicSubnet)
			publicSubnetIds = append(publicSubnetIds, publicSubnet.ID())
			// tmp_publicSubnetIds = append(tmp_publicSubnetIds, publicSubnet.ID())

			_, err = AddSubnetToRouteTable(publicSubnet.ID(), publicRouteTable.ID(), os.Getenv("PUBLIC_SUBNET_A_PREFIX")+"-"+strconv.Itoa(i))
			if err != nil {
				return err
			}

			privateSubnet, err := CreateSubnet(az.Names[i/2], "private-subnet-"+strconv.Itoa(i+1), awsVpc.ID(), blocks[i+1], false, os.Getenv("PVT_SUBNET_PREFIX"))
			if err != nil {
				return err
			}
			privateSubnetIds = append(privateSubnetIds, privateSubnet.ID())

			_, err = AddSubnetToRouteTable(privateSubnet.ID(), privateRouteTable.ID(), os.Getenv("PVT_SUBNET_A_PREFIX")+"-"+strconv.Itoa(i))
		}

		privateSubnetIdsInput := pulumi.StringArrayInput(privateSubnetIds)
		// publicSubnetIdsInput := pulumi.StringArrayInput(tmp_publicSubnetIds)

		// Create subnet group
		pvtSubnetGroup, err := CreateSubnetGroup("private-subnets", privateSubnetIdsInput)
		// pvtSubnetGroup, err := CreateSubnetGroup("public-subnets", publicSubnetIdsInput)

		// Create security groups
		loadBalancerSecGrp, err := CreateLoadBalancerSecurityGroup(awsVpc.ID())
		if err != nil {
			return err
		}

		securityGrp, err := CreateApplicationSecurityGroup(awsVpc.ID(), loadBalancerSecGrp.ID())
		if err != nil {
			return err
		}

		UpdateLoadBalancerSecurityGroup(loadBalancerSecGrp.ID(), securityGrp.ID())

		// Create RDS Security Group
		dbSecGroup, err := CreateRDSSecurityGroup(awsVpc.ID(), securityGrp.ID())
		if err != nil {
			return err
		}

		UpdateApplicationSecurityGroup(securityGrp.ID(), dbSecGroup.ID())

		// Fetch the correct AMI from the source
		ami, err := GetAmi()
		if err != nil {
			return err
		}

		fmt.Println("AMI Id:")
		fmt.Println(ami.Id)

		// Create RDS parameter group
		paraGrp, err := CreateRDSParameterGroup()
		if err != nil {
			return err
		}

		// Create RDS Database
		rdsd, err := CreateRDSDatabase(pvtSubnetGroup.Name, paraGrp.Name, pulumi.StringOutput(dbSecGroup.ID()))

		// Create EC2 instance afer RDS Instance has been created
		amiId := os.Getenv("AMI_ID")
		if strings.TrimSpace(amiId) == "" {
			amiId = ami.Id
		}

		// Create target group
		targetGrp, err := CreateTargetGroup(awsVpc.ID())

		// Create load balancer
		loadBalancer, err := CreateLoadBalancer(publicSubnetIds, loadBalancerSecGrp.ID())

		// Add listener
		AddListener(loadBalancer.Arn, targetGrp.Arn)

		// CloudWatchAgentIam Profile with role
		iamProfile, err := CreateCloudAgentIAMProfile()
		if err != nil {
			return err
		}

		// Create SNS topic
		topic, err := CreateStandardTopic()

		// Create launch template
		userData := GetEncodedUserData(rdsd, topic.Arn)
		launchTemplate, _ := CreateLaunchTemplate(pulumi.String(ami.Id), securityGrp.ID(), userData, iamProfile)

		// Attach Load Balancer A record
		AttachLoadBalancerAlias(loadBalancer)

		CreateAutoScaler(launchTemplate.ID(), publicSubnetIds, targetGrp.Arn)

		// Create service account on GCP
		_, srvPvtKey, _ := CreateServiceAccount()

		// Create bucker
		bucket, err := CreateGcpBucket()

		// Create Dynamo DB table
		dynamoDb, err := CreateDynamoDB()

		// Create Lambda
		CreateLambdaDependencies()
		lambda, err := CreateLambda(topic.Arn, srvPvtKey, bucket.Name, dynamoDb.Name)
		if err != nil {
			fmt.Println("Failed to create lambda function", err)
		}

		// Subscribe the lambda function to the topic
		TopicSubscription(topic.Arn, lambda.Arn)

		return nil
	})
}

func GetCidrBlocks() []string {
	smasklen := os.Getenv("MASK")
	masklen, _ := strconv.Atoi(smasklen)
	noSubnets := os.Getenv("NO_SUBNETS")
	fnoSubnets, _ := strconv.ParseFloat(noSubnets, 64)
	msk := int(math.Ceil(math.Log2(fnoSubnets)))
	n := iplib.NewNet4(net.ParseIP(os.Getenv("CIDR")), masklen)
	sub, _ := n.Subnet(masklen + msk)
	var ans []string
	for _, l := range sub {
		ans = append(ans, l.String())
	}

	return ans
}
