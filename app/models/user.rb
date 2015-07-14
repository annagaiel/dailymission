class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  #Set up Gravatar
  include Gravtastic
	gravtastic :secure => true,
              :filetype => :gif,
              :size => 120

  has_many :task, dependent: :destroy
end
