@export()
@description('Parse a resource ID into its components')
func parseResourceId(resourceId string) object => {
  SubscriptionId: split(resourceId, '/')[2]
  ResourceGroup: split(resourceId, '/')[4]
  Name: last(split(resourceId, '/'))
}
