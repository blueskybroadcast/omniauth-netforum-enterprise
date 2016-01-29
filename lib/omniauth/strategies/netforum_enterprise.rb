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
        Account.find_by_event_code(event_code).slug
      end

      def get_user_info(access_token)
        wsdl = options.client_options.site + options.client_options.wsdl

        ::NetforumEnterprise.configure do
          wsdl wsdl
        end

        if service = ::NetforumEnterprise.authenticate(options.client_options.username, options.client_options.password)
          customer_key = service.web_validate(access_token)
          customer = service.get_individual_information(customer_key)
          {
            id: customer[:cst_id],
            first_name: customer[:ind_first_name],
            last_name: customer[:ind_last_name],
            email: customer[:eml_address],
            cst_key: customer[:ind_cst_key],
            member_flag: customer[:cst_member_flag]
          }
        else
          {}
        end
      end

      private

      def authorize_url
        options.client_options.site + options.client_options.authorize_url
      end
    end
  end
end
