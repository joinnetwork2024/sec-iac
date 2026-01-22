locals {
  # Define a map for your common tags
  common_tags = {
    Name        = "AI Training Data"
    Environment = "Dev"
    DataType    = "Sensitive-ML"
  }
}