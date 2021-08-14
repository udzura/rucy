lambda do |ctx|
  if ctx.minor == 9
    return 0
  else
    return 1
  end
end
