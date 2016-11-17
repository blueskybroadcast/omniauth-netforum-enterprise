require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class NetforumEnterprise < OmniAuth::Strategies::OAuth2

      option :name, 'netforum_enterprise'

      option :client_options, {
        site: 'MUST BE SET',
        return_to_slug: nil,
        alternative_site: nil,
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
        token = request.params['ssoToken'] || request.params['Token']
        if token
          self.access_token = {
            token: token,
            token_expires: 60
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + get_slug(request.params)
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
        if ::NetforumEnterprise.configuration.wsdl.nil?
          ::NetforumEnterprise.configure do |config|
            config.wsdl = wsdl
          end
        end
        customer = {}
        ::NetforumEnterprise.authenticate(username, password) do |auth|
          customer_key = auth.web_validate access_token
          customer_info = auth.get_individual_information customer_key
          customer_committee_codes = get_user_committees(auth, customer_key)
          customer =
          {
            id: customer_info[:cst_id],
            first_name: customer_info[:ind_first_name],
            last_name: customer_info[:ind_last_name],
            email: customer_info[:eml_address],
            cst_key: customer_info[:ind_cst_key],
            member_flag: customer_info[:cst_member_flag],
            committee_codes: customer_committee_codes.map(&:cmt_code)
          }
        end
        customer
      end

      def get_user_committees(auth, customer_key)
        return [] unless options.client_options.use_committee_group_sync
        auth.get_customer_committees customer_key
      end

      private

      def authorize_url
        if options.client_options.alternative_site.present?
          options.client_options.alternative_site
        else
          options.client_options.site + options.client_options.authorize_url
        end
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
