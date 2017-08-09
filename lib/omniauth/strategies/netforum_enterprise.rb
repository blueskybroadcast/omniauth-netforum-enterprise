require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class NetforumEnterprise < OmniAuth::Strategies::OAuth2

      option :name, 'netforum_enterprise'

      option :app_options, { app_event_id: nil }

      option :client_options, {
        site: 'MUST BE SET',
        return_to_slug: nil,
        alternative_site: nil,
        custom_api_endpoint: nil,
        authorize_url: '/eWeb/DynamicPage.aspx?WebCode=LoginRequired',
        wsdl: '/xweb/secure/netForumXML.asmx?WSDL',
        username: 'MUST BE SET',
        password: 'MUST BE SET',
        use_committee_group_sync: false
      }

      uid { raw_info[:id] }

      info do
        raw_info
      end

      def request_phase
        site = session['omniauth.params']['eventcode']
        origin = session['omniauth.params']['origin']
        redirect_link = if options.client_options.alternative_site.present?
                          authorize_url + "?Site=#{site}&ReturnUrl=" + callback_url + "?Token={token}&origin=#{origin}"
                        else
                          authorize_url + "&Site=#{site}&URL_success=" + callback_url + '?ssoToken={token}'
                        end

        redirect redirect_link
      end

      def callback_phase
        slug = get_slug(request.params)
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
        self.env['omniauth.app_event_id'] = @app_event.id

        token = request.params['ssoToken'] || request.params['Token']
        if token
          self.access_token = {
            token: token,
            token_expires: 60
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + slug
          call_app!
        else
          @app_event.logs.create(level: 'error', text: "Netforum Enterprise SSO Failure: 'Token' parameter is absent!")
          @app_event.fail!
          fail!(:invalid_credentials)
        end
      rescue StandardError => e
        @app_event.try(:fail!)
        raise e
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token])
      end

      def get_slug(params)
        if params['Site']
          Provider.find_by_event_code(params['Site'])&.account.slug
        elsif params['origin']
          params['origin'].gsub(/\//, '')
        else
          options.client_options.return_to_slug
        end
      end

      def get_user_info(access_token)
        customer = {}
        client.authenticate(username, password) do |auth|
          create_request_and_response_logs('Authentication', auth)

          customer_key = auth.web_validate access_token
          create_request_and_response_logs('Web Validate', auth)

          customer_info = auth.get_individual_information customer_key
          create_request_and_response_logs('Get Individual Information', auth)

          customer_committee_codes = if options.client_options.use_committee_group_sync
                                       committees = auth.get_customer_committees customer_key
                                       create_request_and_response_logs('Get Customer Committees', auth)
                                       committees
                                     else
                                       []
                                     end

          customer = {
            id: customer_info[:cst_id],
            first_name: customer_info[:ind_first_name],
            last_name: customer_info[:ind_last_name],
            email: customer_info[:eml_address],
            cst_key: customer_info[:ind_cst_key],
            member_flag: customer_info[:cst_member_flag],
            committee_codes: customer_committee_codes.map(&:cmt_code)
          }
        end

        if customer[:id]
          @app_event.update(raw_data: {
            user_info: {
              uid: customer[:id],
              email: customer[:email],
              first_name: customer[:first_name],
              last_name: customer[:last_name]
            }
          })
        else
          @app_event.fail!
        end

        customer
      end

      private

      def authorize_url
        if options.client_options.alternative_site.present?
          options.client_options.alternative_site
        else
          options.client_options.site + options.client_options.authorize_url
        end
      end

      def client
        @client ||= ::NetforumEnterprise.configure { |config| config.wsdl = wsdl }
      end

      def password
        options.client_options.password
      end

      def username
        options.client_options.username
      end

      def wsdl
        options.client_options.custom_api_endpoint.presence ||
          (options.client_options.site + options.client_options.wsdl)
      end

      def provider_name
        options.name
      end

      def create_request_and_response_logs(operation_name, client)
        request_log_text = "#{provider_name.upcase} #{operation_name} Request:\nPOST #{client.last_request.url}, headers: #{client.last_request.headers}\n#{client.last_request.body}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        response_log_text = "#{provider_name.upcase} #{operation_name} Response (code: #{client.last_response.code}):\n#{client.last_response.body}"
        response_log_level = client.last_response.code == 200 ? 'info' : 'error'
        @app_event.logs.create(level: response_log_level, text: response_log_text)
        @app_event.fail! if response_log_level == 'error'
      end
    end
  end
end
