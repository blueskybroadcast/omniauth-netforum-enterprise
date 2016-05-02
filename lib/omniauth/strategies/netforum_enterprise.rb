require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class NetforumEnterprise < OmniAuth::Strategies::OAuth2

      option :name, 'netforum_enterprise'

      option :client_options, {
        site: 'MUST BE SET',
        authorize_url: '/eWeb/DynamicPage.aspx?webcode=login',
        wsdl: '/xweb/secure/netForumXML.asmx?WSDL',
        username: 'MUST BE SET',
        password: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        raw_info
      end

      def request_phase
        site = session['omniauth.params']['eventcode']
        redirect authorize_url + "&Site=#{site}&URL_success=" + callback_url + "?ssoToken={token}"
      end

      def callback_phase
        if request.params['ssoToken']
          self.access_token = {
            :token =>  request.params['ssoToken'],
            :token_expires => 60
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + get_slug(request.params['Site'])
          call_app!
        else
          fail!(:invalid_credentials)
        end
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token])
      end

      def get_slug(event_code)
        Provider.find_by_event_code(event_code)&.account.slug
      end

      def get_user_info(access_token)
        if ::NetforumEnterprise.configuration.wsdl.nil?
          ::NetforumEnterprise.configure do |config|
            config.wsdl = wsdl
          end
        end
        customer = {}
        ::NetforumEnterprise.authenticate(username, password) do |auth|
          customer_key = auth.web_validate access_token
          customer_info = auth.get_individual_information customer_key
          customer =
          {
            id: customer_info[:cst_id],
            first_name: customer_info[:ind_first_name],
            last_name: customer_info[:ind_last_name],
            email: customer_info[:eml_address],
            cst_key: customer_info[:ind_cst_key],
            member_flag: customer_info[:cst_member_flag]
          }
        end
        customer
      end

      private

      def authorize_url
        options.client_options.site + options.client_options.authorize_url
      end

      def password
        options.client_options.password
      end

      def username
        options.client_options.username
      end

      def wsdl
        options.client_options.site + options.client_options.wsdl
      end
    end
  end
end
