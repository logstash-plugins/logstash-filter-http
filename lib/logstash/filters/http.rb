# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/json'
require 'logstash/namespace'
require 'logstash/plugin_mixins/http_client'
require 'logstash/plugin_mixins/ecs_compatibility_support'
require 'logstash/plugin_mixins/ecs_compatibility_support/target_check'
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'

# Logstash HTTP Filter
# This filter calls a defined URL and saves the answer into a specified field.
#
class LogStash::Filters::Http < LogStash::Filters::Base

  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

  include LogStash::PluginMixins::HttpClient[:with_deprecated => true]

  config_name 'http'

  VALID_VERBS = ['GET', 'HEAD', 'PATCH', 'DELETE', 'POST', 'PUT']

  config :url, :validate => :string, :required => true
  config :verb, :validate => VALID_VERBS, :required => false, :default => 'GET'
  config :headers, :validate => :hash, :required => false, :default => {}
  config :query, :validate => :hash, :required => false, :default => {}
  config :body, :required => false
  config :body_format, :validate => ['text', 'json'], :default => "text"

  # default [body] (legacy) required to be specified in ECS mode
  config :target_body, :validate => :field_reference
  # default [headers] (legacy) or [@metadata][filter][http][response][headers] in ECS mode
  config :target_headers, :validate => :field_reference

  # Append values to the `tags` field when there has been no
  # successful match or json parsing error
  config :tag_on_request_failure, :validate => :array, :default => ['_httprequestfailure']
  config :tag_on_json_failure, :validate => :array, :default => ['_jsonparsefailure']

  def initialize(*params)
    super

    @target_body ||= ecs_select[disabled: '[body]', v1: false]
    if @target_body.eql? false # user needs to specify target in ECS mode
      @logger.error missing_config_message(:target_body)
      raise LogStash::ConfigurationError.new "Wrong configuration (in ecs_compatibility mode #{ecs_compatibility.inspect})"
    end

    @target_headers ||= ecs_select[disabled: '[headers]', v1: '[@metadata][filter][http][response][headers]']
  end

  def register
    # nothing to see here
    @verb = verb.downcase
  end

  def filter(event)
    url_for_event = event.sprintf(@url)
    headers_sprintfed = sprintf_object(event, @headers)
    if !headers_sprintfed.key?('content-type') && !headers_sprintfed.key?('Content-Type')
      headers_sprintfed['content-type'] = @body_format == "json" ? "application/json" : "text/plain"
    end
    query_sprintfed = sprintf_object(event, @query)
    body_sprintfed = sprintf_object(event, @body)
    # we don't need to serialize strings and numbers
    if @body_format == "json" && body_sprintfed.kind_of?(Enumerable)
      body_sprintfed = LogStash::Json.dump(body_sprintfed)
    end

    options = { :headers => headers_sprintfed, :query => query_sprintfed, :body => body_sprintfed }

    @logger.debug? && @logger.debug('processing request', :url => url_for_event, :headers => headers_sprintfed, :query => query_sprintfed)
    client_error = nil

    begin
      code, response_headers, response_body = request_http(@verb, url_for_event, options)
    rescue => e
      client_error = e
    end

    if client_error
      @logger.error('error during HTTP request',
                    :url => url_for_event, :body => body_sprintfed,
                    :client_error => client_error.message)
      @tag_on_request_failure.each { |tag| event.tag(tag) }
    elsif !code.between?(200, 299)
      @logger.error('error during HTTP request',
                    :url => url_for_event, :code => code,
                    :headers => response_headers,
                    :response => response_body)
      @tag_on_request_failure.each { |tag| event.tag(tag) }
    else
      @logger.debug? && @logger.debug('success received',
                                      :code => code, :headers => response_headers, :body => response_body)
      process_response(response_body, response_headers, event)
      filter_matched(event)
    end
  end # def filter

  private

  def missing_config_message(name)
    <<-EOF
Missing a required setting for the http filter plugin:

  filter {
    http {
      #{name} => # SETTING MISSING
      ...
    }
  }
EOF
  end

  def request_http(verb, url, options = {})
    response = client.http(verb, url, options)
    [response.code, response.headers, response.body]
  end

  def sprintf_object(event, obj)
    case obj
    when Array
      obj.map {|el| sprintf_object(event, el) }
    when Hash
      obj.inject({}) {|acc, (k,v)| acc[sprintf_object(event, k)] = sprintf_object(event, v); acc }
    when String
      event.sprintf(obj)
    else
      obj
    end
  end

  def process_response(body, headers, event)
    event.set(@target_headers, headers)
    return if @verb == 'head' # Since HEAD requests will not contain body, we need to set only header

    return if body.nil? #Return on empty bodys (e.g. 204 response)

    if headers_has_json_content_type?(headers)
      begin
        parsed = LogStash::Json.load(body)
        event.set(@target_body, parsed)
      rescue => e
        if @logger.debug?
          @logger.warn('JSON parsing error', :message => e.message, :body => body)
        else
          @logger.warn('JSON parsing error', :message => e.message)
        end
        @tag_on_json_failure.each { |tag| event.tag(tag) }
      end
    else
      event.set(@target_body, body.strip)
    end
  end

  ##
  # @param headers [String] or [Array]
  # @return resolved content-type
  def headers_has_json_content_type?(headers)
    # content-type might be an array or string with ; separated
    headers = headers.fetch("content-type", "")
    headers = headers.kind_of?(Array) ? headers : headers.split(';')
    headers.map(&:strip).include?("application/json")
  end

end # class LogStash::Filters::Rest
