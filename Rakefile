require 'bundler'
Bundler::GemHelper.install_tasks

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

require 'appraisal'

namespace :cover_me do
  desc "Generates and opens code coverage report."
  task :report do
    require 'cover_me'
    CoverMe.complete!
  end
end
task :spec do
  Rake::Task['cover_me:report'].invoke
end

desc 'Default: run unit specs.'
task :default do
  sh "bundle exec rake appraisal:install && bundle exec rake appraisal spec"
end
