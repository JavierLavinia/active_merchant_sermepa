# encoding: utf-8
module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    module Integrations #:nodoc:
      module Sermepa
        # Sermepa/Servired Spanish Virtual POS Gateway
        #
        # Support for the Spanish payment gateway provided by Sermepa, part of Servired,
        # one of the main providers in Spain to Banks and Cajas.
        #
        # Requires the :terminal_id, :commercial_id, and :secret_key to be set in the credentials
        # before the helper can be used. Credentials may be overwriten when instantiating the helper
        # if required or instead of the global variable. Optionally, the :key_type can also be set to 
        # either 'sha1_complete' or 'sha1_extended', where the later is the default case. This
        # is a configurable option in the Sermepa admin which you may or may not be able to access.
        # If nothing seems to work, try changing this.
        #
        # Ensure the gateway is configured correctly. Synchronization should be set to Asynchronous
        # and the parameters in URL option (Parámetros en las URLs) should be set to true unless
        # the notify_url is provided. During development on localhost ensuring this option is set
        # is especially important as there is no other way to confirm a successful purchase.
        #
        # Your view for a payment form might look something like the following:
        #
        #   <%= payment_service_for @transaction.id, 'Company name', :amount => @transaction.amount, :currency => 'EUR', :service => :sermepa do |service| %>
        #     <% service.description     @sale.description %>
        #     <% service.customer_name   @sale.client.name %>
        #     <% service.notify_url      notify_sale_url(@sale) %>
        #     <% service.success_url     win_sale_url(@sale) %>
        #     <% service.failure_url     fail_sale_url(@sale) %>
        #    
        #     <%= submit_tag "PAY!" %>
        #   <% end %>
        #
        #
        # 
        class Helper < ActiveMerchant::Billing::Integrations::Helper
          include PostsData

          class << self
            # Credentials should be set as a hash containing the fields:
            #  :terminal_id, :commercial_id, :secret_key, :key_type (optional)
            attr_accessor :credentials
          end

          mapping :account,     'Ds_Merchant_MerchantName'

          mapping :currency,    'Ds_Merchant_Currency'
          mapping :amount,      'Ds_Merchant_Amount'

          mapping :order,       'Ds_Merchant_Order'
          mapping :description, 'Ds_Merchant_ProductDescription'
          mapping :client,      'Ds_Merchant_Titular'

          mapping :notify_url,  'Ds_Merchant_MerchantURL'
          mapping :success_url, 'Ds_Merchant_UrlOK'
          mapping :failure_url, 'Ds_Merchant_UrlKO'

          mapping :language,    'Ds_Merchant_ConsumerLanguage'

          mapping :transaction_type, 'Ds_Merchant_TransactionType'

          mapping :customer_name, 'Ds_Merchant_Titular'

          #### Special Request Specific Fields ####
          mapping :signature,   'Ds_Signature'
          mapping :signature_version, 'Ds_SignatureVersion'
          mapping :merchant_parameters, 'Ds_MerchantParameters'
          ########

          # ammount should always be provided in cents!
          def initialize(order, account, options = {})
            self.credentials = options.delete(:credentials) if options[:credentials]
            super(order, account, options)

            add_field 'Ds_Merchant_MerchantCode', credentials[:commercial_id]
            add_field 'Ds_Merchant_Terminal', credentials[:terminal_id]
            #add_field mappings[:transaction_type], '0' # Default Transaction Type
            self.transaction_type = :authorization
          end

          # Allow credentials to be overwritten if needed
          def credentials
            @credentials || self.class.credentials
          end
          def credentials=(creds)
            @credentials = (self.class.credentials || {}).dup.merge(creds)
          end

          def amount=(money)
            cents = money.respond_to?(:cents) ? money.cents : money
            if money.is_a?(String) || cents.to_i <= 0
              raise ArgumentError, 'money amount must be either a Money object or a positive integer in cents.'
            end
            add_field mappings[:amount], cents.to_i
          end

          def order=(order_id)
            order_id = order_id.to_s
            if order_id !~ /^[0-9]{4}/ && order_id.length <= 8
              order_id = ('0' * 4) + order_id
            end
            regexp = /^[0-9]{4}[0-9a-zA-Z]{0,8}$/
            raise "Invalid order number format! First 4 digits must be numbers" if order_id !~ regexp
            add_field mappings[:order], order_id
          end

          def currency=( value )
            add_field mappings[:currency], Sermepa.currency_code(value) 
          end

          def language=(lang)
            add_field mappings[:language], Sermepa.language_code(lang)
          end

          def transaction_type=(type)
            add_field mappings[:transaction_type], Sermepa.transaction_code(type)
          end

          def form_fields
            add_field mappings[:signature], sign_request
            @fields
          end

          def merchant_parameters_json
            {
              DS_MERCHANT_CURRENCY: @fields['Ds_Merchant_Currency'],
              DS_MERCHANT_AMOUNT: @fields['Ds_Merchant_Amount'],
              DS_MERCHANT_TRANSACTIONTYPE: @fields['Ds_Merchant_TransactionType'],
              DS_MERCHANT_MERCHANTDATA: @fields['Ds_Merchant_Product_Description'] || "",
              DS_MERCHANT_TERMINAL: "00#{credentials[:terminal_id]}",
              DS_MERCHANT_MERCHANTCODE: credentials[:commercial_id],
              DS_MERCHANT_ORDER: @fields['Ds_Merchant_Order'],
              DS_MERCHANT_MERCHANTURL: @fields['Ds_Merchant_MerchantURL'],
              DS_MERCHANT_URLOK: @fields['Ds_Merchant_UrlOK'],
              DS_MERCHANT_URLKO: @fields['Ds_Merchant_UrlKO']
            }.to_json
          end

          def merchant_parameters_base64_json
            Base64.strict_encode64(merchant_parameters_json)
          end

          # Generate a signature authenticating the current request.
          # Values included in the signature are determined by the the type of
          # transaction.
          def sign_request
            # By default OpenSSL generates an all-zero array for the encriptation vector
             # You can read it here: http://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-i-iv-3D
             # If you want to declare it, you can take a look at the next couple of lines
             #bytes = Array.new(8,0)
             #iv = bytes.map(&:chr).join
             # We need to decode the secret key
             key = Base64.strict_decode64(credentials[:secret_key])
             # In thee cipher initialization we need to speficy the encryptation like method-length-mode (http://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL/Cipher.html#method-c-new).
             # Sermepa needs DES3 in CBC mode
             # The direct way the declare it's: des-ede3-cbc
             # You can also declare like 'des3' wich use CBC mode by default
             des3 = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')
             # OpenSSL use by default PKCS padding. But Sermepa (mcrypt_encrypt PHP function) use zero padding.
             # OpenSSL do not allow zero padding. So we need to disable the default padding and make zero padding by hand
             # Padding in cryptography is to fill the data with especial characteres in order to use the data in blocks of N (https://en.wikipedia.org/wiki/Padding_(cryptography))
             # We need to use blocks of 8 bytes
             block_length = 8
             # We tell OpenSSL not to pad
             des3.padding = 0
             # We want to encrypt
             des3.encrypt
             # Key set
             des3.key = key
             #des3.iv = iv
             order_number = @fields["Ds_Merchant_Order"]
             # Here is the 'magic'. Instead use the default OpenSSL padding (PKCS). We fill with \0 till the data have
             # a multiple of the block size (8, 16, 24...)
             order_number += "\0" until order_number.bytesize % block_length == 0
             # For example: the string "123456789" will be transform in "123456789\x00\x00\x00\x00\x00\x00\x00"
             # data must be in blocks of 8 or the update will break
             key_des3 = des3.update(order_number) + des3.final
             # The next step is to encrypt in SHA256 the resulting des3 key with the base64 json
             result = OpenSSL::HMAC.digest('sha256', key_des3, merchant_parameters_base64_json)
             # The last step is to encode the data in base64
             Base64.strict_encode64(result)
          end

          # Send a manual request for the currently prepared transaction.
          # This is an alternative to the normal view helper and is useful
          # for special types of transaction.
          def send_transaction
            body = merchant_parameters_base64_json

            headers = { }
            headers['Content-Length'] = body.size.to_s
            headers['User-Agent'] = "Active Merchant -- http://activemerchant.org"
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

            # Return the raw response data
            ssl_post(Sermepa.operations_url, "entrada="+CGI.escape(body), headers)
          end

        end
      end
    end
  end
end
