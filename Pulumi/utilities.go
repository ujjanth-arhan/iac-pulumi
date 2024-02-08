package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/google/go-github/v56/github"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/appautoscaling"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/dynamodb"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lambda"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/sns"
	"github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/serviceaccount"
	"github.com/pulumi/pulumi-gcp/sdk/v7/go/gcp/storage"

	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/autoscaling"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/lb"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/rds"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/route53"
	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/vpc"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var ctx *pulumi.Context

func SetPulumiContext(context *pulumi.Context) {
	ctx = context
}

func CreateVpc(name string, cidrBlock string, tags string, tenancy string) (*ec2.Vpc, error) {
	awsVpc, err := ec2.NewVpc(ctx, name, &ec2.VpcArgs{
		EnableDnsHostnames: pulumi.BoolPtr(true),
		CidrBlock:          pulumi.String(cidrBlock),
		Tags: pulumi.StringMap{
			"Name": pulumi.String(tags),
		},
		InstanceTenancy: pulumi.String(tenancy),
	})

	return awsVpc, err
}

func CreateInternetGateway(name string, vpcId pulumi.StringPtrInput, tags string) (*ec2.InternetGateway, error) {
	igw, err := ec2.NewInternetGateway(ctx, name, &ec2.InternetGatewayArgs{
		VpcId: vpcId,
		Tags: pulumi.StringMap{
			"Name": pulumi.String(tags),
		},
	})

	return igw, err
}

func GetAvailabilityZones() (*aws.GetAvailabilityZonesResult, error) {
	availabilityZones, err := aws.GetAvailabilityZones(ctx, nil, nil)

	return availabilityZones, err
}

func CreateSubnet(az string, name string, vpcId pulumi.StringInput, cidrBlock string, isPublicSubnet bool, tags string) (*ec2.Subnet, error) {
	subnet, err := ec2.NewSubnet(ctx, name, &ec2.SubnetArgs{
		VpcId:     vpcId,
		CidrBlock: pulumi.String(cidrBlock),
		Tags: pulumi.StringMap{
			"Name": pulumi.String(tags),
		},
		MapPublicIpOnLaunch: pulumi.Bool(isPublicSubnet),
		AvailabilityZone:    pulumi.String(az),
	})

	return subnet, err
}

func CreateRouteTable(vpcId pulumi.StringInput, name string, tags string) (*ec2.RouteTable, error) {
	routeTable, err := ec2.NewRouteTable(ctx, name, &ec2.RouteTableArgs{
		VpcId: vpcId,
		Tags: pulumi.StringMap{
			"Name": pulumi.String(tags),
		},
	})

	return routeTable, err
}

func AddSubnetToRouteTable(subnetId pulumi.StringInput, routeTableId pulumi.StringInput, name string) (*ec2.RouteTableAssociation, error) {
	rta, err := ec2.NewRouteTableAssociation(ctx, name, &ec2.RouteTableAssociationArgs{
		SubnetId:     subnetId,
		RouteTableId: routeTableId,
	})

	return rta, err
}

// Todo: Change egress for all sec groups?
func CreateApplicationSecurityGroup(vpcId pulumi.StringInput, secGroupId pulumi.StringInput) (*ec2.SecurityGroup, error) {
	return ec2.NewSecurityGroup(ctx, "application security group", &ec2.SecurityGroupArgs{
		Description: pulumi.String("Allow SSH, API inbound traffic"),
		VpcId:       vpcId,
		Ingress: ec2.SecurityGroupIngressArray{
			&ec2.SecurityGroupIngressArgs{
				Description: pulumi.String("SSH"),
				FromPort:    pulumi.Int(22),
				ToPort:      pulumi.Int(22),
				Protocol:    pulumi.String("tcp"),
				CidrBlocks: pulumi.StringArray{
					pulumi.String(os.Getenv("INTERNET_GATEWAY")),
				},
			},
			&ec2.SecurityGroupIngressArgs{
				Description: pulumi.String("REST API"),
				FromPort:    pulumi.Int(8080),
				ToPort:      pulumi.Int(8080),
				Protocol:    pulumi.String("tcp"),
				SecurityGroups: pulumi.StringArray{
					secGroupId,
				},
			},
		},
		Egress: ec2.SecurityGroupEgressArray{
			&ec2.SecurityGroupEgressArgs{
				FromPort: pulumi.Int(443),
				ToPort:   pulumi.Int(443),
				Protocol: pulumi.String("tcp"),
				CidrBlocks: pulumi.StringArray{
					pulumi.String(os.Getenv("INTERNET_GATEWAY")),
				},
				Ipv6CidrBlocks: pulumi.StringArray{
					pulumi.String("::/0"),
				},
			},
		},
		Tags: pulumi.StringMap{
			"Name": pulumi.String("application-security-group"),
		},
	})
}

func CreateLoadBalancerSecurityGroup(vpcId pulumi.StringPtrInput) (*ec2.SecurityGroup, error) {
	return ec2.NewSecurityGroup(ctx, "load balancer security group", &ec2.SecurityGroupArgs{
		Description: pulumi.String("Allow HTTP, HTTPS inbound traffic"),
		VpcId:       vpcId,
		Ingress: ec2.SecurityGroupIngressArray{
			&ec2.SecurityGroupIngressArgs{
				Description: pulumi.String("HTTP"),
				FromPort:    pulumi.Int(80),
				ToPort:      pulumi.Int(80),
				Protocol:    pulumi.String("tcp"),
				CidrBlocks: pulumi.StringArray{
					pulumi.String(os.Getenv("INTERNET_GATEWAY")),
				},
			},
			&ec2.SecurityGroupIngressArgs{
				Description: pulumi.String("HTTPS"),
				FromPort:    pulumi.Int(443),
				ToPort:      pulumi.Int(443),
				Protocol:    pulumi.String("tcp"),
				CidrBlocks: pulumi.StringArray{
					pulumi.String(os.Getenv("INTERNET_GATEWAY")),
				},
			},
		},
		Tags: pulumi.StringMap{
			"Name": pulumi.String("load-balancer"),
		},
	})
}

func UpdateLoadBalancerSecurityGroup(securityGroupId pulumi.IDOutput, destinationSecGrpId pulumi.IDOutput) {
	applicationPort, _ := strconv.Atoi(os.Getenv("APPLICATION_PORT"))
	vpc.NewSecurityGroupEgressRule(ctx, "UpdatedEgress", &vpc.SecurityGroupEgressRuleArgs{
		SecurityGroupId:           securityGroupId,
		IpProtocol:                pulumi.String("tcp"),
		FromPort:                  pulumi.Int(applicationPort),
		ToPort:                    pulumi.Int(applicationPort),
		ReferencedSecurityGroupId: destinationSecGrpId,
	})
}

func CreateRDSSecurityGroup(vpcId pulumi.StringInput, secGrp pulumi.StringInput) (*ec2.SecurityGroup, error) {
	return ec2.NewSecurityGroup(ctx, "database", &ec2.SecurityGroupArgs{
		Description: pulumi.String("Security group for RDS traffic"),
		VpcId:       vpcId,

		Ingress: ec2.SecurityGroupIngressArray{
			&ec2.SecurityGroupIngressArgs{
				Description:    pulumi.String("PostgreSQL"),
				FromPort:       pulumi.Int(5432),
				ToPort:         pulumi.Int(5432),
				Protocol:       pulumi.String("tcp"),
				SecurityGroups: pulumi.StringArray{secGrp},
			},
		},
		Egress: ec2.SecurityGroupEgressArray{
			&ec2.SecurityGroupEgressArgs{
				FromPort: pulumi.Int(0),
				ToPort:   pulumi.Int(0),
				Protocol: pulumi.String("-1"),
				CidrBlocks: pulumi.StringArray{
					pulumi.String(os.Getenv("INTERNET_GATEWAY")),
				},
				Ipv6CidrBlocks: pulumi.StringArray{
					pulumi.String("::/0"),
				},
			},
		},
		Tags: pulumi.StringMap{
			"Name": pulumi.String("database-security-group"),
		},
	})
}

func GetAmi() (*ec2.LookupAmiResult, error) {
	return ec2.LookupAmi(ctx, &ec2.LookupAmiArgs{Owners: []string{os.Getenv("DEV_ACCOUNT_ID"), os.Getenv("DEMO_ACCOUNT_ID")}, MostRecent: pulumi.BoolRef(true)}, nil)
}

func CreateEC2Instance(amiId string, subnetId pulumi.IDOutput, securityGroupId pulumi.IDOutput, otpt pulumi.StringOutput, iamProfile *iam.InstanceProfile) (*ec2.Instance, error) {
	return ec2.NewInstance(ctx, "webapp", &ec2.InstanceArgs{
		Ami:                 pulumi.String(amiId),
		InstanceType:        pulumi.String(os.Getenv("INSTANCE_TYPE")),
		KeyName:             pulumi.String("amazon"),
		VpcSecurityGroupIds: pulumi.StringArray{securityGroupId},
		SubnetId:            subnetId,
		RootBlockDevice:     ec2.InstanceRootBlockDevicePtrInput(ec2.InstanceRootBlockDeviceArgs{VolumeSize: pulumi.IntPtr(25)}),
		UserData:            otpt,
		IamInstanceProfile:  iamProfile,
	})
}

func CreateSubnetGroup(groupName string, subnetIds pulumi.StringArrayInput) (*rds.SubnetGroup, error) {
	return rds.NewSubnetGroup(ctx, groupName, &rds.SubnetGroupArgs{
		SubnetIds: subnetIds,
	})
}

func CreateRDSParameterGroup() (*rds.ParameterGroup, error) {
	return rds.NewParameterGroup(ctx, "rds-parameter-group", &rds.ParameterGroupArgs{
		Family:      pulumi.String("postgres15"),
		Description: pulumi.String("The postgres RDS group"),
	})
}

func CreateRDSDatabase(subnetGroupName pulumi.StringOutput, paraGrpName pulumi.StringOutput, secGrpId pulumi.StringOutput) (*rds.Instance, error) {
	return rds.NewInstance(ctx, "csye6225", &rds.InstanceArgs{
		Engine: pulumi.String("postgres"),
		// EngineVersion:              pulumi.String("PostgreSQL 15.3-R2"),
		DbName:                     pulumi.String(os.Getenv("RDS_NAME")),
		MultiAz:                    pulumi.Bool(false),
		BackupRetentionPeriod:      pulumi.IntPtr(0),
		Username:                   pulumi.String(os.Getenv("RDS_USER_NAME")),
		Password:                   pulumi.String(os.Getenv("RDS_USER_PASSWD")),
		InstanceClass:              pulumi.String("db.t3.micro"),
		StorageType:                pulumi.String("gp2"),
		AllocatedStorage:           pulumi.Int(20),
		DbSubnetGroupName:          subnetGroupName,
		PubliclyAccessible:         pulumi.Bool(false),
		VpcSecurityGroupIds:        pulumi.StringArray{secGrpId},
		PerformanceInsightsEnabled: pulumi.Bool(false),
		ParameterGroupName:         paraGrpName,
		SkipFinalSnapshot:          pulumi.Bool(true),
		ApplyImmediately:           pulumi.Bool(true),
	})
}

func GetEncodedUserData(rdsi *rds.Instance, snsTopicArn pulumi.StringOutput) pulumi.StringOutput {
	return pulumi.All(rdsi.Address, snsTopicArn).ApplyT(func(args []interface{}) string {
		os.Setenv("PSGR_CONNECTION", "host="+args[0].(string)+" user="+os.Getenv("PSGR_USER")+" password="+os.Getenv("PSGR_USER_PASSWORD")+" port="+os.Getenv("PORT")+" sslmode="+os.Getenv("SSL_MODE"))
		os.Setenv("DB_CONNECTION", "host="+args[0].(string)+" user="+os.Getenv("PSGR_USER")+" password="+os.Getenv("PSGR_USER_PASSWORD")+" port="+os.Getenv("PORT")+" sslmode="+os.Getenv("SSL_MODE")+" dbname="+os.Getenv("DB_NAME"))
		usrData := fmt.Sprintf(`#!/bin/bash
sudo touch %s
echo ENVIRONMENT="%s" >> %s
echo PSGR_CONNECTION="%s" >> %s
echo DB_NAME="%s" >> %s
echo DB_CONNECTION="%s" >> %s
echo USERS_FILE="%s" >> %s
echo LOG_FILE="%s" >> %s
echo STATSD_SERVER="%s" >> %s
echo STATSD_PREFIX="%s" >> %s
echo BCRYPT_COST=%s >> %s
echo AWS_SNS_TOPIC_ARN="%s" >> %s
echo SNS_MESSAGE_GROUP_ID="%s" >> %s
echo AWS_REGION="%s" >> %s
sudo chown -R user1:csye6225 %s
instance=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq ".instanceId")
cat /opt/user1/appfiles/tmp-cloudwatch-config.json | jq ".logs .logs_collected .files .collect_list[0] .log_stream_name=$instance" | cat > /opt/user1/appfiles/cloudwatch-config.json
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:%s -s`,
			os.Getenv("ENV_FILE"),
			os.Getenv("ENVIRONMENT"), os.Getenv("ENV_FILE"),
			os.Getenv("PSGR_CONNECTION"), os.Getenv("ENV_FILE"),
			os.Getenv("DB_NAME"), os.Getenv("ENV_FILE"),
			os.Getenv("DB_CONNECTION"), os.Getenv("ENV_FILE"),
			os.Getenv("USERS_FILE"), os.Getenv("ENV_FILE"),
			os.Getenv("LOG_FILE"), os.Getenv("ENV_FILE"),
			os.Getenv("STATSD_SERVER"), os.Getenv("ENV_FILE"),
			os.Getenv("STATSD_PREFIX"), os.Getenv("ENV_FILE"),
			os.Getenv("BCRYPT_COST"), os.Getenv("ENV_FILE"),
			args[1].(string), os.Getenv("ENV_FILE"),
			os.Getenv("SNS_MESSAGE_GROUP_ID"), os.Getenv("ENV_FILE"),
			os.Getenv("AWS_REGION"), os.Getenv("ENV_FILE"),
			os.Getenv("ENV_FILE"),
			os.Getenv("CLOUD_CONFIG_FILE"))
		usrData = base64.StdEncoding.EncodeToString([]byte(usrData))
		return usrData
	}).(pulumi.StringOutput)
}

func CreateCloudAgentIAMProfile() (*iam.InstanceProfile, error) {

	assumeRole, _ := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Effect: pulumi.StringRef("Allow"),
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type: "Service",
						Identifiers: []string{
							"ec2.amazonaws.com",
						},
					},
				},
				Actions: []string{
					"sts:AssumeRole",
				},
			},
		},
	}, nil)

	role, _ := iam.NewRole(ctx, "CloudWatchAgentServerRole", &iam.RoleArgs{
		AssumeRolePolicy: pulumi.StringPtr(assumeRole.Json),
	})

	iam.NewRolePolicyAttachment(ctx, "role-attachment", &iam.RolePolicyAttachmentArgs{
		Role:      role.Name,
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"),
	})

	snsPublishPolicyRaw, _ := json.Marshal(map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Action": []string{
					"sns:Publish*",
				},
				"Effect":   "Allow",
				"Resource": "*",
			},
		},
	})

	snsPublishPolicy := string(snsPublishPolicyRaw)
	publishPolicy, _ := iam.NewPolicy(ctx, "publish-policy", &iam.PolicyArgs{
		Path:        pulumi.String("/"),
		Description: pulumi.String("SNS publish policy"),
		Policy:      pulumi.String(snsPublishPolicy),
	})

	iam.NewRolePolicyAttachment(ctx, "role-attachment-sns", &iam.RolePolicyAttachmentArgs{
		Role: role.Name,
		// PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonSNSFullAccess"),
		PolicyArn: publishPolicy.Arn,
	})

	return iam.NewInstanceProfile(ctx, "cloudagent-profile", &iam.InstanceProfileArgs{
		Role: role,
	})
}

func AttachARecord(ec2Ip pulumi.StringOutput) (*route53.Record, error) {
	subdomain, _ := ctx.GetConfig("iac-pulumi:subdomain")
	hostZoneId, _ := ctx.GetConfig("iac-pulumi:hostedzone")
	return route53.NewRecord(ctx, "EC2Instance", &route53.RecordArgs{
		ZoneId: pulumi.StringInput(pulumi.String(hostZoneId)),
		Name:   pulumi.String(subdomain),
		Type:   pulumi.String("A"),
		Ttl:    pulumi.Int(60),
		Records: pulumi.StringArray{
			ec2Ip,
		},
	})
}

func CreateTargetGroup(vpcId pulumi.StringInput) (*lb.TargetGroup, error) {
	targetPort, err := strconv.Atoi(os.Getenv("APPLICATION_PORT"))
	if err != nil {
		fmt.Println(err)
	}

	return lb.NewTargetGroup(ctx, "TargetGroup", &lb.TargetGroupArgs{
		TargetType:          pulumi.String("instance"),
		Port:                pulumi.Int(targetPort),
		Protocol:            pulumi.String("HTTP"),
		VpcId:               vpcId,
		IpAddressType:       pulumi.String("ipv4"),
		HealthCheck:         &lb.TargetGroupHealthCheckArgs{Path: pulumi.String("/healthz"), HealthyThreshold: pulumi.Int(2)},
		DeregistrationDelay: pulumi.Int(10),
	})
}

func CreateLoadBalancer(subnetIds pulumi.StringArrayInput, securityGroupId pulumi.StringInput) (*lb.LoadBalancer, error) {
	return lb.NewLoadBalancer(ctx, "LoadBalancer", &lb.LoadBalancerArgs{
		Internal:                 pulumi.Bool(false),
		LoadBalancerType:         pulumi.String("application"),
		IpAddressType:            pulumi.String("ipv4"),
		SecurityGroups:           pulumi.StringArray{securityGroupId},
		Subnets:                  subnetIds,
		EnableDeletionProtection: pulumi.Bool(false),
	})

}

func AddListener(loadBalancerArn pulumi.StringInput, targetGroupArn pulumi.StringInput) (*lb.Listener, error) {
	certificateArn, _ := ctx.GetConfig("acm:certificate")
	return lb.NewListener(ctx, "Listener", &lb.ListenerArgs{
		LoadBalancerArn: loadBalancerArn,
		Port:            pulumi.Int(443),
		Protocol:        pulumi.String("HTTPS"),
		SslPolicy:       pulumi.String("ELBSecurityPolicy-2016-08"),
		CertificateArn:  pulumi.String(certificateArn),
		DefaultActions: lb.ListenerDefaultActionArray{
			&lb.ListenerDefaultActionArgs{
				Type:           pulumi.String("forward"),
				TargetGroupArn: targetGroupArn,
				// Forward: lb.ListenerDefaultActionForwardArgs{TargetGroups: lb.ListenerDefaultActionForwardTargetGroupArray{lb.ListenerDefaultActionForwardTargetGroupArgs{Arn: targetGroupArn}}},
			},
		},
	})
}

// Todo: Create a key dynamically
func CreateLaunchTemplate(amiId pulumi.String, secGrpId pulumi.IDOutput, userData pulumi.StringOutput, iamProfile *iam.InstanceProfile) (*ec2.LaunchTemplate, error) {
	return ec2.NewLaunchTemplate(ctx, "LaunchTemplate", &ec2.LaunchTemplateArgs{
		Description:           pulumi.String("Launch template to be used for AutoScaling"),
		ImageId:               amiId,
		KeyName:               pulumi.String("amazon"),
		PrivateDnsNameOptions: ec2.LaunchTemplatePrivateDnsNameOptionsArgs{EnableResourceNameDnsARecord: pulumi.Bool(true), EnableResourceNameDnsAaaaRecord: pulumi.Bool(false), HostnameType: pulumi.String("ip-name")},
		InstanceType:          pulumi.String(os.Getenv("INSTANCE_TYPE")),
		VpcSecurityGroupIds:   pulumi.StringArray{secGrpId},
		UserData:              userData,
		IamInstanceProfile:    ec2.LaunchTemplateIamInstanceProfileArgs{Arn: iamProfile.Arn},
		DisableApiTermination: pulumi.BoolPtr(false),
		// MetadataOptions:       ec2.LaunchTemplateMetadataOptionsArgs{HttpEndpoint: pulumi.String("disabled")},
	})
}

func CreateAutoScaler(launchTemplateId pulumi.IDOutput, subnetIds pulumi.StringArray, targetGroupArn pulumi.StringOutput) (*autoscaling.Group, error) {
	autoScaling, err := autoscaling.NewGroup(ctx, "autoscaling-group", &autoscaling.GroupArgs{
		// AvailabilityZones: availabilityZones,
		DesiredCapacity: pulumi.Int(1),
		MaxSize:         pulumi.Int(3),
		MinSize:         pulumi.Int(1),
		LaunchTemplate: &autoscaling.GroupLaunchTemplateArgs{
			Id:      launchTemplateId,
			Version: pulumi.String("$Latest"),
		},
		Name:                   pulumi.String("asg_launch_config"),
		TargetGroupArns:        pulumi.StringArray{targetGroupArn},
		HealthCheckGracePeriod: pulumi.Int(50),
		HealthCheckType:        pulumi.String("ELB"),
		Tags:                   autoscaling.GroupTagArray{autoscaling.GroupTagArgs{Key: pulumi.String("key"), PropagateAtLaunch: pulumi.Bool(true), Value: pulumi.String("AutoScalingGroup")}},
		// LaunchConfiguration:    pulumi.String(""),
		DefaultCooldown:    pulumi.Int(60),
		VpcZoneIdentifiers: subnetIds,
	})

	upscalePol, _ := autoscaling.NewPolicy(ctx, "upscale", &autoscaling.PolicyArgs{
		PolicyType:           pulumi.String("SimpleScaling"),
		AutoscalingGroupName: autoScaling.Name,
		ScalingAdjustment:    pulumi.Int(1),
		AdjustmentType:       pulumi.String("ChangeInCapacity"),
		Cooldown:             pulumi.Int(30),
	})

	cloudwatch.NewMetricAlarm(ctx, "upscale-alarm", &cloudwatch.MetricAlarmArgs{
		ComparisonOperator: pulumi.String("GreaterThanOrEqualToThreshold"),
		EvaluationPeriods:  pulumi.Int(1),
		MetricName:         pulumi.String("CPUUtilization"),
		Namespace:          pulumi.String("AWS/EC2"),
		Period:             pulumi.Int(60),
		Statistic:          pulumi.String("Average"),
		Threshold:          pulumi.Float64(5),
		Dimensions: pulumi.StringMap{
			"AutoScalingGroupName": autoScaling.Name,
		},
		AlarmDescription: pulumi.String("This metric monitors ec2 cpu utilization"),
		AlarmActions: pulumi.Array{
			upscalePol.Arn,
		},
	})

	downscalePol, _ := autoscaling.NewPolicy(ctx, "downscale", &autoscaling.PolicyArgs{
		PolicyType:           pulumi.String("SimpleScaling"),
		AutoscalingGroupName: autoScaling.Name,
		ScalingAdjustment:    pulumi.Int(-1),
		AdjustmentType:       pulumi.String("ChangeInCapacity"),
		Cooldown:             pulumi.Int(30),
	})

	cloudwatch.NewMetricAlarm(ctx, "downscale-alarm", &cloudwatch.MetricAlarmArgs{
		ComparisonOperator: pulumi.String("LessThanOrEqualToThreshold"),
		EvaluationPeriods:  pulumi.Int(1),
		MetricName:         pulumi.String("CPUUtilization"),
		Namespace:          pulumi.String("AWS/EC2"),
		Period:             pulumi.Int(60),
		Statistic:          pulumi.String("Average"),
		Threshold:          pulumi.Float64(3),
		Dimensions: pulumi.StringMap{
			"AutoScalingGroupName": autoScaling.Name,
		},
		AlarmDescription: pulumi.String("This metric monitors ec2 cpu utilization"),
		AlarmActions: pulumi.Array{
			downscalePol.Arn,
		},
	})

	return autoScaling, err
}

func AttachLoadBalancerAlias(loadBalancer *lb.LoadBalancer) (*route53.Record, error) {
	subdomain, _ := ctx.GetConfig("iac-pulumi:subdomain")
	hostZoneId, _ := ctx.GetConfig("iac-pulumi:hostedzone")
	//loadBalancer.ZoneId.ApplyT(func(lba string) (*route53.Record, error) {
	return route53.NewRecord(ctx, "LoadBalancerAlias", &route53.RecordArgs{
		Aliases:        route53.RecordAliasArray{&route53.RecordAliasArgs{EvaluateTargetHealth: pulumi.Bool(true), Name: loadBalancer.DnsName, ZoneId: loadBalancer.ZoneId}},
		AllowOverwrite: pulumi.Bool(true),
		ZoneId:         pulumi.String(hostZoneId),
		Name:           pulumi.String(subdomain),
		Type:           pulumi.String("A"),
	})
	//})

	return nil, nil
}

func UpdateApplicationSecurityGroup(applicationSecGroupId pulumi.IDOutput, rdsSecGroupId pulumi.IDOutput) {
	prt, _ := strconv.Atoi(os.Getenv("PORT"))
	vpc.NewSecurityGroupEgressRule(ctx, "UpdatedApplicationEgress", &vpc.SecurityGroupEgressRuleArgs{
		SecurityGroupId:           applicationSecGroupId,
		IpProtocol:                pulumi.String("tcp"),
		FromPort:                  pulumi.Int(prt),
		ToPort:                    pulumi.Int(prt),
		ReferencedSecurityGroupId: rdsSecGroupId,
	})
}

func CreateStandardTopic() (*sns.Topic, error) {
	return sns.NewTopic(ctx, "SubmissionSNS", &sns.TopicArgs{
		ContentBasedDeduplication: pulumi.Bool(false),
		FifoTopic:                 pulumi.Bool(false),
	})
}

func TopicSubscription(topicArn pulumi.StringOutput, lambdaArn pulumi.StringOutput) {
	sns.NewTopicSubscription(ctx, "LambdaSubscription", &sns.TopicSubscriptionArgs{
		Topic:    topicArn,
		Protocol: pulumi.String("lambda"),
		Endpoint: lambdaArn,
	})
}

func CreateLambda(topicArn pulumi.StringOutput, pvtKey *serviceaccount.Key, bucketName pulumi.StringOutput, dynamoTableName pulumi.StringOutput) (*lambda.Function, error) {

	assumeRole, err := iam.GetPolicyDocument(ctx, &iam.GetPolicyDocumentArgs{
		Statements: []iam.GetPolicyDocumentStatement{
			{
				Effect: pulumi.StringRef("Allow"),
				Principals: []iam.GetPolicyDocumentStatementPrincipal{
					{
						Type: "Service",
						Identifiers: []string{
							"lambda.amazonaws.com",
							"sns.amazonaws.com",
						},
					},
				},
				Actions: []string{
					"sts:AssumeRole",
				},
			},
		},
	}, nil)

	if err != nil {
		fmt.Println("Error creating lamda policy", err)
	}

	iamForLambda, err := iam.NewRole(ctx, "iamForLambda", &iam.RoleArgs{
		AssumeRolePolicy: pulumi.String(assumeRole.Json),
	})

	if err != nil {
		fmt.Println("Error creating IAM for lambda", err)
	}

	iam.NewRolePolicyAttachment(ctx, "LambdaBasicExecutionRule", &iam.RolePolicyAttachmentArgs{
		Role:      pulumi.Any(iamForLambda.Name),
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
	})

	iam.NewRolePolicyAttachment(ctx, "LambdaDynamoRole", &iam.RolePolicyAttachmentArgs{
		Role:      pulumi.Any(iamForLambda.Name),
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"),
	})

	evironmentVariables := pulumi.StringMap{
		"MAILGUN_DOMAIN":           pulumi.String(os.Getenv("MAILGUN_DOMAIN")),
		"MAILGUN_PVT_API_KEY":      pulumi.String(os.Getenv("MAILGUN_PVT_API_KEY")),
		"SENDER":                   pulumi.String(os.Getenv("SENDER")),
		"SUBJECT":                  pulumi.String(os.Getenv("SUBJECT")),
		"BUCKET":                   bucketName,
		"GCP_CREDENTIALS_LOCATION": pulumi.String(os.Getenv("GCP_CREDENTIALS_LOCATION")),
		"MAIL_TABLE":               dynamoTableName,
		"GCP_CREDS_JSON": pvtKey.PrivateKey.ApplyT(func(x string) string {
			file, _ := base64.URLEncoding.DecodeString(x)
			return string(file)
		}).(pulumi.StringOutput),
	}

	lmb, err := lambda.NewFunction(ctx, "SubmissionsLambda", &lambda.FunctionArgs{
		Architectures: pulumi.StringArray{pulumi.String("arm64")},
		Code:          pulumi.NewFileArchive("lambda.zip"),
		//S3Bucket:    pulumi.String("samplebktsadf"),
		//S3Key:       pulumi.String("lambda.zip"),
		Role:        iamForLambda.Arn,
		Runtime:     pulumi.String("provided.al2"),
		Handler:     pulumi.String("hello.handler"),
		Environment: lambda.FunctionEnvironmentArgs{Variables: evironmentVariables},
	})

	lambda.NewPermission(ctx, "allowCloudwatch", &lambda.PermissionArgs{
		Action:    pulumi.String("lambda:InvokeFunction"),
		Function:  lmb.Name,
		Principal: pulumi.String("sns.amazonaws.com"),
		SourceArn: topicArn,
	})

	return lmb, err
}

func CreateDynamoDB() (*dynamodb.Table, error) {
	partitionKey := os.Getenv("DYNAMO_DB_PARTITION_KEY")
	tbl, err := dynamodb.NewTable(ctx, "mail-details", &dynamodb.TableArgs{
		Attributes: dynamodb.TableAttributeArray{
			&dynamodb.TableAttributeArgs{
				Name: pulumi.String(partitionKey),
				Type: pulumi.String("S"),
			},
		},
		HashKey:       pulumi.String(partitionKey),
		ReadCapacity:  pulumi.IntPtr(1),
		WriteCapacity: pulumi.IntPtr(1),
	})

	dynamodbTableReadTarget, _ := appautoscaling.NewTarget(ctx, "dynamodbTableReadTarget", &appautoscaling.TargetArgs{
		MaxCapacity:       pulumi.Int(10),
		MinCapacity:       pulumi.Int(1),
		ResourceId:        tbl.Name.ApplyT(func(x string) string { return "table/" + x }).(pulumi.StringOutput),
		ScalableDimension: pulumi.String("dynamodb:table:ReadCapacityUnits"),
		ServiceNamespace:  pulumi.String("dynamodb"),
	})

	dynamodbTableWriteTarget, _ := appautoscaling.NewTarget(ctx, "dynamodbTableWriteTarget", &appautoscaling.TargetArgs{
		MaxCapacity:       pulumi.Int(10),
		MinCapacity:       pulumi.Int(1),
		ResourceId:        tbl.Name.ApplyT(func(x string) string { return "table/" + x }).(pulumi.StringOutput),
		ScalableDimension: pulumi.String("dynamodb:table:WriteCapacityUnits"),
		ServiceNamespace:  pulumi.String("dynamodb"),
	})

	appautoscaling.NewPolicy(ctx, "dynamodbTableReadPolicy", &appautoscaling.PolicyArgs{
		PolicyType:        pulumi.String("TargetTrackingScaling"),
		ResourceId:        dynamodbTableReadTarget.ResourceId,
		ScalableDimension: dynamodbTableReadTarget.ScalableDimension,
		ServiceNamespace:  dynamodbTableReadTarget.ServiceNamespace,
		TargetTrackingScalingPolicyConfiguration: &appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs{
			PredefinedMetricSpecification: &appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs{
				PredefinedMetricType: pulumi.String("DynamoDBReadCapacityUtilization"),
			},
			TargetValue: pulumi.Float64(70),
		},
	})

	appautoscaling.NewPolicy(ctx, "dynamodbTableWritePolicy", &appautoscaling.PolicyArgs{
		PolicyType:        pulumi.String("TargetTrackingScaling"),
		ResourceId:        dynamodbTableWriteTarget.ResourceId,
		ScalableDimension: dynamodbTableWriteTarget.ScalableDimension,
		ServiceNamespace:  dynamodbTableWriteTarget.ServiceNamespace,
		TargetTrackingScalingPolicyConfiguration: &appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs{
			PredefinedMetricSpecification: &appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs{
				PredefinedMetricType: pulumi.String("DynamoDBWriteCapacityUtilization"),
			},
			TargetValue: pulumi.Float64(70),
		},
	})

	return tbl, err
}

func CreateServiceAccount() (*serviceaccount.Account, *serviceaccount.Key, error) {
	srvacc, err := serviceaccount.NewAccount(ctx, "serviceAccount", &serviceaccount.AccountArgs{
		AccountId:   pulumi.String(os.Getenv("GCP_ACCOUNT_ID")),
		DisplayName: pulumi.String("Pulumi Account"),
		Description: pulumi.String("Pulumi resource dev account"),
	})

	devProject, _ := ctx.GetConfig("gcp:project")
	projects.NewIAMBinding(ctx, "project", &projects.IAMBindingArgs{
		Members: pulumi.StringArray{
			srvacc.Email.ApplyT(func(x string) pulumi.String { return pulumi.String("serviceAccount:" + x) }).(pulumi.StringOutput),
		},
		Project: pulumi.String(devProject),
		Role:    pulumi.String("roles/storage.objectCreator"),
	})

	pvtkey, _ := serviceaccount.NewKey(ctx, "serviceKey", &serviceaccount.KeyArgs{
		ServiceAccountId: srvacc.Name,
		PrivateKeyType:   pulumi.String("TYPE_GOOGLE_CREDENTIALS_FILE"),
	})

	return srvacc, pvtkey, err
}

func CreateGcpBucket() (*storage.Bucket, error) {
	return storage.NewBucket(ctx, os.Getenv("BUCKET"), &storage.BucketArgs{
		Location:               pulumi.String("US-CENTRAL1"),
		PublicAccessPrevention: pulumi.String("enforced"),
		ForceDestroy:           pulumi.Bool(true),
	})
}

func CreateLambdaDependencies() {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_ACCESS_TOKEN"))
	//fileContent, dirContent, response, err := client.Repositories.GetContents(context.Background(), "cloud-ujjanth-arhan", "serverless", "README.md", nil)
	//println(fileContent.Name)
	//println(dirContent)
	//println(response)
	repo, _, err := client.Repositories.Get(context.Background(), "cloud-ujjanth-arhan", "serverless")
	if err != nil {
		println("Create lambda dependencies ", repo, " ", err)
	}

}
